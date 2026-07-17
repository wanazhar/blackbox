#!/usr/bin/env bash
# Deterministic PTY fidelity probe for blackbox supervised runs (1.4 Phase D).
# Modes selected via first argument.
set -euo pipefail
mode="${1:-all}"

emit_ansi() {
  # Colors + cursor movement + alternate screen enter/leave (best-effort)
  printf '\033[32mgreen\033[0m \033[1mbold\033[0m\n'
  printf '\033[2J\033[Hcleared\n'
  printf '\033[?1049hALT\033[?1049l\n'
}

emit_unicode() {
  printf 'café 日本語 👨‍💻 wide:中\n'
  # Combining acute on e
  printf 'e\xcc\x81 combined\n'
}

emit_long_line() {
  # 4k line without trailing newline first, then newline
  python3 - <<'PY' 2>/dev/null || dd if=/dev/zero bs=1 count=4096 2>/dev/null | tr '\0' 'x'
print("L" * 4096, end="")
print("")
print("done_long")
PY
}

emit_no_nl() {
  printf 'no_trailing_newline'
}

emit_binaryish() {
  # Invalid UTF-8 mid-stream
  printf 'before'
  printf '\xff\xfe'
  printf 'after\n'
}

emit_stream() {
  # Moderate stream volume
  i=0
  while [ "$i" -lt 200 ]; do
    printf 'line-%03d-abcdefghijklmnopqrstuvwxyz\n' "$i"
    i=$((i + 1))
  done
}

emit_exit() {
  echo "exit_marker=${1:-0}"
  exit "${1:-0}"
}

case "$mode" in
  ansi) emit_ansi; emit_exit 0 ;;
  unicode) emit_unicode; emit_exit 0 ;;
  long) emit_long_line; emit_exit 0 ;;
  no_nl) emit_no_nl; exit 0 ;;
  binary) emit_binaryish; emit_exit 0 ;;
  stream) emit_stream; emit_exit 0 ;;
  exit42) echo ready; emit_exit 42 ;;
  pgid)
    # Print process group / session for PTY supervision checks
    echo "PID=$$"
    echo "PPID=$PPID"
    echo "PGID=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ' || echo unknown)"
    echo "SID=$(ps -o sid= -p $$ 2>/dev/null | tr -d ' ' || echo unknown)"
    if [ -t 1 ]; then echo "STDOUT_TTY=1"; else echo "STDOUT_TTY=0"; fi
    emit_exit 0
    ;;
  storm)
    # Short-lived process storm under the supervised shell
    n="${2:-80}"
    i=0
    while [ "$i" -lt "$n" ]; do
      /bin/true
      /bin/echo "storm-$i" >/dev/null
      i=$((i + 1))
    done
    echo "storm_done=$n"
    emit_exit 0
    ;;
  all)
    emit_ansi
    emit_unicode
    emit_long_line
    emit_binaryish
    emit_stream
    emit_exit 0
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac
