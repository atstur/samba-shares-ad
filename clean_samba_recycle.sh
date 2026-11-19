#!/bin/bash
set -euo pipefail

export LC_ALL=C.UTF-8

LOG="clean-samba-recycle"
SHARE_ROOT="/public"
DAYS=30

# Защита от параллельного запуска
mkdir -p /run/lock 2>/dev/null || true
exec 9>"/run/lock/${LOG}.lock"
if ! flock -n 9; then
    logger -t "$LOG" "SKIP: cleanup already running"
    exit 0
fi

while IFS= read -r -d '' RECYCLE; do
    USER_DIR=$(dirname "$RECYCLE")
    USER_NAME=$(basename "$USER_DIR")

    # 1. Считаем количество и размер файлов старше 30 дней по ctime
    STATS=$(find "$RECYCLE" -type f -ctime +"$DAYS" -printf '%s\n' | awk '{c++; s+=$1} END {printf "%d %d", c+0, s+0}')
    DEL_COUNT=${STATS% *}
    DEL_BYTES=${STATS#* }

    # 2. Удаляем старые файлы и пишем одну строку в системный журнал
    if [ "$DEL_COUNT" -gt 0 ]; then
        DEL_MB=$(awk -v b="$DEL_BYTES" 'BEGIN {printf "%.1f", b/1048576}')
        find "$RECYCLE" -type f -ctime +"$DAYS" -delete
        logger -t "$LOG" "[$USER_NAME] удалено файлов: $DEL_COUNT (${DEL_MB} МБ)"
    fi

    # 3. Удаляем пустые подпапки внутри корзины (кроме самой .recycle)
    find "$RECYCLE" -mindepth 1 -depth -type d -empty -delete

done < <(find "$SHARE_ROOT" -mindepth 2 -maxdepth 2 -type d -name ".recycle" -print0)

logger -t "$LOG" "DONE: очистка корзин завершена"