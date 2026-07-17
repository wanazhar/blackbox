#!/usr/bin/env bash
# Neutrality probe — dumps child-visible process identity for direct-vs-recorded comparison.
# Output is machine-parseable KEY=value lines on stdout.
set -euo pipefail

echo "PROBE_VERSION=1"
echo "ARGC=$#"
i=0
for a in "$@"; do
  # length-prefixed to preserve spaces / empty args
  printf 'ARGV_%d_LEN=%d\n' "$i" "${#a}"
  printf 'ARGV_%d=%s\n' "$i" "$a"
  i=$((i + 1))
done

echo "CWD=$(pwd)"
echo "UID=$(id -u)"
echo "EUID=$(id -u)"
echo "GID=$(id -g)"
echo "PID=$$"
echo "PPID=$PPID"
echo "PGID=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ' || echo unknown)"
echo "SID=$(ps -o sid= -p $$ 2>/dev/null | tr -d ' ' || echo unknown)"

if [ -t 0 ]; then echo "STDIN_TTY=1"; else echo "STDIN_TTY=0"; fi
if [ -t 1 ]; then echo "STDOUT_TTY=1"; else echo "STDOUT_TTY=0"; fi
if [ -t 2 ]; then echo "STDERR_TTY=1"; else echo "STDERR_TTY=0"; fi

# Sorted environment (filter nothing — comparison layer decides allowed diffs).
echo "ENV_BEGIN"
env | LC_ALL=C sort
echo "ENV_END"

# Count BLACKBOX_* vars visible to this process.
bb_count=0
bb_keys=""
while IFS= read -r line; do
  key="${line%%=*}"
  case "$key" in
    BLACKBOX_*)
      bb_count=$((bb_count + 1))
      bb_keys="${bb_keys}${bb_keys:+,}${key}"
      ;;
  esac
done <<EOF
$(env)
EOF
echo "BLACKBOX_ENV_COUNT=${bb_count}"
echo "BLACKBOX_ENV_KEYS=${bb_keys}"

echo "PROBE_OK=1"
exit 0
