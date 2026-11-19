#!/bin/bash
set -uo pipefail

export LC_ALL=C.UTF-8

ORIG_NAME="${1:-}"
LOG="mk-share-folder"
SHARE_ROOT="/public"
# параметр перед саими скриптом rootpreexecclose=yes
# --- 1. Проверка на пустое имя ---
if [ -z "$ORIG_NAME" ]; then
    logger -t "$LOG" "ERROR: no username passed"
    exit 1
fi

# --- 2. Нижний регистр ---
USER_NAME="${ORIG_NAME,,}"

# --- 3. Срезать домен, если пришёл в виде 'beer\test' или 'beer+test' ---
USER_NAME="${USER_NAME##*\\}"
USER_NAME="${USER_NAME##*+}"

# --- 4. Отсечь "." и ".." (regex их пропускает, т.к. точка в классе) ---
if [[ "$USER_NAME" == "." || "$USER_NAME" == ".." ]]; then
    logger -t "$LOG" "SECURITY: path traversal attempt '$USER_NAME'"
    exit 1
fi

# --- 5. Валидация имени (отсекает машинные учётки из-за $, /, \, пробелы, @ и т.п.) ---
if [[ ! "$USER_NAME" =~ ^[a-z0-9._-]+$ ]]; then
    logger -t "$LOG" "SECURITY: invalid username '$USER_NAME'"
    exit 1
fi

# --- 6. Защита от параллельного запуска для одного пользователя ---
mkdir -p /run/lock 2>/dev/null || true
LOCK_FILE="/run/lock/${LOG}-${USER_NAME}.lock"
exec 9>"$LOCK_FILE"
trap 'exec 9>&- 2>/dev/null' EXIT
if ! flock -w 5 9; then
    logger -t "$LOG" "ERROR: timeout waiting for lock on $USER_NAME"
    exit 1
fi

# --- 7. Резолв UID ДО создания папки ---
USER_UID=$(id -u "$ORIG_NAME" 2>/dev/null || id -u "$USER_NAME" 2>/dev/null || true)
if [ -z "$USER_UID" ]; then
    logger -t "$LOG" "ERROR: cannot resolve UID for $ORIG_NAME"
    exit 1
fi

# --- 8. Читаем homeDirectory из AD ---
RAW=$(net ads search -P \
    "(&(objectClass=user)(sAMAccountName=${USER_NAME}))" \
    homeDirectory 2>/dev/null || true)

if [ -z "$RAW" ]; then
    logger -t "$LOG" "ERROR: net ads search returned empty for $USER_NAME (DC unavailable?)"
    exit 1
fi

# --- 9. Base64 / LDIF ---
if printf '%s' "$RAW" | grep -q '^homeDirectory:: '; then
    B64=$(awk '
        /^homeDirectory:: / { collecting=1; sub(/^homeDirectory:: /, ""); b64=$0; next }
        collecting && /^ /   { sub(/^ /, ""); b64=b64 $0; next }
        collecting           { collecting=0 }
        END { print b64 }
    ' <<< "$RAW" | tr -d '[:space:]')
    while [ $(( ${#B64} % 4 )) -ne 0 ]; do B64="${B64}="; done
    HOMEDIR=$(printf '%s' "$B64" | base64 -d 2>/dev/null || true)
else
    HOMEDIR=$(awk '/^homeDirectory: / { sub(/^homeDirectory: /, ""); print; exit }' <<< "$RAW")
fi

HOMEDIR=$(printf '%s' "$HOMEDIR" | tr -d '\r\n' | sed 's/[[:space:]]*$//')

# --- 10. Пустой атрибут   Если при отсутствии homeDirectory нужно отклонять само подключение к этой шаре поменять exit на 1 ---
if [ -z "$HOMEDIR" ]; then
    logger -t "$LOG" "DENY $USER_NAME: homeDirectory not set in AD"
    exit 0
fi

USER_DIR="$SHARE_ROOT/$USER_NAME"

# --- 11. Функция: root-владелец, 750, ACL для пользователя ---
apply_permissions() {
    local target="$1"
    local recursive_flag="${2:-}"

    if ! mkdir -p "$target"; then
        logger -t "$LOG" "ERROR: mkdir failed for $target"
        return 1
    fi
    if ! chown ${recursive_flag:+"$recursive_flag"} 0:0 "$target"; then
        logger -t "$LOG" "ERROR: chown failed for $target"
        return 1
    fi
    # chmod ДО setfacl: setfacl сам поднимет mask обратно до rwx
    if ! chmod 750 "$target"; then
        logger -t "$LOG" "ERROR: chmod failed for $target"
        return 1
    fi
    if ! setfacl ${recursive_flag:+"$recursive_flag"} -m "u:${USER_UID}:rwx" "$target"; then
        logger -t "$LOG" "ERROR: setfacl access failed for $target"
        return 1
    fi
    if ! setfacl ${recursive_flag:+"$recursive_flag"} -d -m "u:${USER_UID}:rwx" "$target"; then
        logger -t "$LOG" "ERROR: setfacl default failed for $target"
        return 1
    fi
    return 0
}

# --- 12. Защита от симлинка для папки юзера ---
if [ -L "$USER_DIR" ]; then
    logger -t "$LOG" "SECURITY: $USER_DIR is a symlink, refusing"
    exit 1
fi

# --- 13. Создание/проверка папки юзера ---
if [ ! -d "$USER_DIR" ]; then
    if ! apply_permissions "$USER_DIR" "-R"; then
        exit 1
    fi
    logger -t "$LOG" "CREATED $USER_DIR for $USER_NAME (UID: $USER_UID)"
else
    # Папка уже есть — проверяем ACL
    ACL_DUMP=$(getfacl -np "$USER_DIR" 2>/dev/null || true)

    # Чужой UID с правом записи? (r-x/r--/--x не считаем — это бэкапы/антивирус)
    OTHER_UID=$(printf '%s\n' "$ACL_DUMP" | awk -F: -v uid="$USER_UID" \
        '/^user:[0-9]+:/ && $2 != uid && $3 ~ /w/ { print $2; exit }')

    if [ -n "$OTHER_UID" ]; then
        ARCHIVE_DIR="${USER_DIR}.old_$(date +%Y%m%d_%H%M%S)"
        logger -t "$LOG" "WARN UID mismatch on $USER_DIR (found writable $OTHER_UID, expected $USER_UID). Archiving to $ARCHIVE_DIR"
        if ! mv "$USER_DIR" "$ARCHIVE_DIR"; then
            logger -t "$LOG" "ERROR: cannot move $USER_DIR to $ARCHIVE_DIR"
            exit 1
        fi
        if ! apply_permissions "$USER_DIR" "-R"; then
            exit 1
        fi
        logger -t "$LOG" "CREATED fresh $USER_DIR for $USER_NAME (UID: $USER_UID), old archived to $ARCHIVE_DIR"
    else
        # Чужого пишущего UID нет. Проверяем владельца, ACL и mask.
        OWNER_GROUP=$(stat -c '%u:%g' "$USER_DIR")
        if [ "$OWNER_GROUP" != "0:0" ] || \
           ! printf '%s\n' "$ACL_DUMP" | grep -q "^user:${USER_UID}:rwx" || \
           ! printf '%s\n' "$ACL_DUMP" | grep -q "^default:user:${USER_UID}:rwx" || \
           ! printf '%s\n' "$ACL_DUMP" | grep -q "^mask::rwx"; then
            logger -t "$LOG" "WARN fixing owner/ACL on $USER_DIR (owner=$OWNER_GROUP)"
            if ! apply_permissions "$USER_DIR" ""; then
                exit 1
            fi
            logger -t "$LOG" "FIXED owner and ACL on $USER_DIR for UID $USER_UID"
        fi
    fi
fi

exit 0