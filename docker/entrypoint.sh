#!/bin/sh
# morfPhoto : point d'entree de l'image Docker.
# SPDX-License-Identifier: GPL-3.0-only
set -eu

# Root uniquement le temps d'attribuer le volume au compte demande, puis on l'abandonne.
if [ "$(id -u)" = "0" ]; then
    PUID="${PUID:-1000}"
    PGID="${PGID:-1000}"
    if [ "$(stat -c %u:%g /data)" != "$PUID:$PGID" ]; then
        chown -R "$PUID:$PGID" /data
    fi
    export HOME=/data
    exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups "$0" "$@"
fi

BASE_URL="http://127.0.0.1:8793"
MARKER="/data/.photos-registered"

# Affiche le code HTTP. La cle passe par stdin : elle n'apparait jamais dans `ps`.
api() {
    if [ -n "${MORFPHOTO_API_KEY:-}" ]; then
        printf 'header = "Authorization: Bearer %s"\n' "$MORFPHOTO_API_KEY" |
            curl -s -o /dev/null -w '%{http_code}' -K - -X POST \
                -H 'Content-Type: application/json' -d "$2" "$BASE_URL$1"
    else
        curl -s -o /dev/null -w '%{http_code}' -X POST \
            -H 'Content-Type: application/json' -d "$2" "$BASE_URL$1"
    fi
}

# Une base neuve n'a aucune selection : sans cela, le conteneur n'indexerait rien.
# Une seule fois (marqueur sur le volume), pour respecter un retrait volontaire ensuite.
register_photos() {
    tries=0
    until curl -fs "$BASE_URL/healthz" >/dev/null 2>&1; do
        tries=$((tries + 1))
        [ "$tries" -lt 60 ] || { echo "morfphoto-entrypoint: service injoignable" >&2; return 0; }
        sleep 1
    done

    code="$(api /api/v1/folders '{"path":"/photos","label":"photos"}' || true)"
    if [ "$code" != "201" ]; then
        echo "morfphoto-entrypoint: declaration de /photos refusee (HTTP $code)" >&2
        return 0
    fi
    : > "$MARKER"

    # 409 : la passe de demarrage tourne encore, on reessaie brievement.
    tries=0
    while [ "$tries" -lt 30 ]; do
        code="$(api /api/v1/index '{"mode":"incremental"}' || true)"
        [ "$code" = "409" ] || return 0
        tries=$((tries + 1))
        sleep 2
    done
}

if [ ! -e "$MARKER" ]; then
    register_photos &
fi

run_clip_worker() {
    backoff=2
    while :; do
        start_ts="$(date +%s)"
        rc=0
        /opt/morfphoto-clip/bin/python /opt/morfphoto-clip/worker.py || rc=$?
        if [ "$rc" -eq 0 ]; then
            return 0
        fi
        end_ts="$(date +%s)"
        if [ $((end_ts - start_ts)) -ge 60 ]; then
            backoff=2
        fi
        echo "morfphoto-entrypoint: CLIP worker exited with code $rc, restarting in ${backoff}s" >&2
        sleep "$backoff"
        backoff=$((backoff * 2))
        if [ "$backoff" -gt 30 ]; then
            backoff=30
        fi
    done
}

export OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-1}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-1}"

if [ -n "${MORFPHOTO_CLIP_DIR:-}" ]; then
    run_clip_worker &
fi

exec "$@"
