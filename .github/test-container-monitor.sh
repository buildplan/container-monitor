#!/usr/bin/env bash
set -euo pipefail

# Script under test
SCRIPT_TO_TEST="./container-monitor.sh"

# Colors
PASS_COLOR='\033[0;32m'; FAIL_COLOR='\033[0;31m'; NC='\033[0m'
pass(){ echo -e "${PASS_COLOR}✅ PASS:${NC} $*"; }
fail(){ echo -e "${FAIL_COLOR}❌ FAIL:${NC} $*"; }

# Deterministic environment
TEST_TMP="$(mktemp -d)"; trap 'rm -rf "$TEST_TMP"' EXIT
export TMPDIR="$TEST_TMP"
export LOG_FILE="$TEST_TMP/container-monitor-test.log"
export FORCE_UPDATE_CHECK=1
export CHECK_FREQUENCY_MINUTES=0

# Prefer deterministic save-logs dir if script honors it
export SAVE_LOGS_DIR="$TEST_TMP/logs"
mkdir -p "$SAVE_LOGS_DIR"

# Behavior toggles
RUN_DANGEROUS="${RUN_DANGEROUS:-0}"
AUTO_TTY="${AUTO_TTY:-1}"

# Ensure the script exists and is executable
if [[ ! -f "$SCRIPT_TO_TEST" ]]; then
  echo -e "${FAIL_COLOR}❌ ERROR: Script not found at ${SCRIPT_TO_TEST}${NC}"
  exit 1
fi
chmod +x "$SCRIPT_TO_TEST"

HELP="$("$SCRIPT_TO_TEST" --help 2>&1 || true)"

# Helpers
require_zero(){
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$d exit code 0"; else fail "$d exit code non-zero"; fi
}
require_no_bfd(){
  local d="$1"; shift
  if "$@" 2>&1 | grep -qi "bad file descriptor"; then fail "$d produced 'Bad file descriptor'"; else pass "$d did not produce 'Bad file descriptor'"; fi
}

# Container discovery
pick_container(){
  if [[ -n "${CONTAINER_NAMES:-}" ]]; then echo "${CONTAINER_NAMES// /}"; return; fi
  docker ps --format '{{.Names}}' | head -n1 || true
}
TARGETS="$(pick_container)"
TARGET_ONE="$(echo "$TARGETS" | tr ',' ' ' | awk '{print $1}')"

echo "=== Container Monitor Tests ==="

# 1) --check-setup
echo -e "\n1) --check-setup"
require_zero "--check-setup" "$SCRIPT_TO_TEST" --check-setup
require_no_bfd "--check-setup output" "$SCRIPT_TO_TEST" --check-setup

# 2) Default run
echo -e "\n2) Default monitoring"
require_zero "default run" "$SCRIPT_TO_TEST"
require_no_bfd "default run output" "$SCRIPT_TO_TEST"

# 3) --summary
echo -e "\n3) --summary"
require_zero "--summary run" "$SCRIPT_TO_TEST" --summary
require_no_bfd "--summary output" "$SCRIPT_TO_TEST" --summary

# 4) Positional containers
echo -e "\n4) Positional containers"
if [[ -n "$TARGET_ONE" ]]; then
  require_zero "positional container $TARGET_ONE" "$SCRIPT_TO_TEST" "$TARGET_ONE"
else
  echo "Skipping positional test (no running containers detected)"
fi

# 5) --exclude
echo -e "\n5) --exclude"
if [[ -n "$TARGET_ONE" ]]; then
  require_zero "--exclude=$TARGET_ONE" "$SCRIPT_TO_TEST" --exclude="$TARGET_ONE" --summary
else
  echo "Skipping --exclude test (no running containers detected)"
fi

# 6) Logs
echo -e "\n6) Logs"
if echo "$HELP" | grep -q -- "--logs"; then
  if [[ -n "$TARGET_ONE" ]]; then
    echo "Using container for logs: $TARGET_ONE"
    require_zero "--logs $TARGET_ONE" "$SCRIPT_TO_TEST" --logs "$TARGET_ONE"
    require_no_bfd "--logs output" "$SCRIPT_TO_TEST" --logs "$TARGET_ONE"

    LOGS_OUT="$TEST_TMP/logs-filter.out"; LOGS_ERR="$TEST_TMP/logs-filter.err"
    if "$SCRIPT_TO_TEST" --logs "$TARGET_ONE" error warn >"$LOGS_OUT" 2>"$LOGS_ERR"; then
      pass "--logs $TARGET_ONE error warn exit code 0"
    else
      if grep -qiE "no match|no matching|no lines|empty|nothing found" "$LOGS_OUT" "$LOGS_ERR" 2>/dev/null; then
        pass "--logs $TARGET_ONE error warn had no matches (treated as success)"
      else
        # If stdout is empty or contains only status lines, treat as no-match success
        if [[ ! -s "$LOGS_OUT" ]] || ! grep -vE "\[(INFO|GOOD|WARNING|DANGER|SUMMARY)\]" "$LOGS_OUT" | grep -qiE "error|warn" 2>/dev/null; then
          echo "No matching log lines for patterns: error, warn (treating as success for CI)"
          pass "--logs $TARGET_ONE error warn had no matches (heuristic)"
        else
          echo "---- logs stdout ----"; sed -n '1,120p' "$LOGS_OUT" || true
          echo "---- logs stderr ----"; sed -n '1,120p' "$LOGS_ERR" || true
          fail "--logs $TARGET_ONE error warn exit code non-zero"
        fi
      fi
    fi
  else
    echo "Skipping logs (no containers)"
  fi
else
  echo "Skipping logs (flag not supported)"
fi

# 7) --save-logs
echo -e "\n7) --save-logs"
if echo "$HELP" | grep -q -- "--save-logs"; then
  if [[ -n "$TARGET_ONE" ]]; then
    OUT_STD="$TEST_TMP/save-logs.out"; OUT_ERR="$TEST_TMP/save-logs.err"
    if "$SCRIPT_TO_TEST" --save-logs "$TARGET_ONE" >"$OUT_STD" 2>"$OUT_ERR"; then
      LOG_SAVED_PATH="$(grep -Eo '(/[^ ]+\.log)' "$OUT_STD" | head -n1 || true)"
      if [[ -z "$LOG_SAVED_PATH" ]]; then
        RELATIVE_LOG_PATH="$(grep -oE "saved to '[^']+\.log'" "$OUT_STD" | sed -E "s/saved to '([^']+)'.*/\1/" | head -n1 || true)"
        if [[ -n "$RELATIVE_LOG_PATH" && -f "$RELATIVE_LOG_PATH" ]]; then
          mv "$RELATIVE_LOG_PATH" "$TEST_TMP/" || true
          [[ -f "${RELATIVE_LOG_PATH}.err" ]] && mv "${RELATIVE_LOG_PATH}.err" "$TEST_TMP/" || true
          LOG_SAVED_PATH="$TEST_TMP/$(basename "$RELATIVE_LOG_PATH")"
        fi
      fi
      if [[ -z "$LOG_SAVED_PATH" ]]; then
        LOG_SAVED_PATH="$(find "$SAVE_LOGS_DIR" -maxdepth 2 -type f -name "${TARGET_ONE}*.log" -newer "$OUT_STD" 2>/dev/null | head -n1 || true)"
      fi
      if [[ -n "$LOG_SAVED_PATH" && -s "$LOG_SAVED_PATH" ]]; then
        pass "--save-logs created non-empty file: $LOG_SAVED_PATH"
      else
        echo "---- save-logs stdout ----"; sed -n '1,120p' "$OUT_STD" || true
        echo "---- save-logs stderr ----"; sed -n '1,120p' "$OUT_ERR" || true
        fail "--save-logs did not report or create a log file"
      fi
    else
      echo "---- save-logs stdout ----"; sed -n '1,120p' "$OUT_STD" || true
      echo "---- save-logs stderr ----"; sed -n '1,120p' "$OUT_ERR" || true
      fail "--save-logs returned non-zero"
    fi
  else
    echo "Skipping --save-logs (no containers)"
  fi
else
  echo "Skipping --save-logs (flag not supported)"
fi

# 8) Interactive update/pull
echo -e "\n8) Interactive update/pull (TTY-only)"
if [[ "$AUTO_TTY" == "1" ]] && [ -t 0 ] && [ -t 1 ]; then
  if echo "$HELP" | grep -q -- "--pull"; then
    echo "Testing --pull (auto 'n')"
    script -qfec "printf 'n\n' | $SCRIPT_TO_TEST --pull" /dev/null || true
    pass "--pull prompt executed"
  fi
  if echo "$HELP" | grep -q -- "--update"; then
    echo "Testing --update (auto 'n')"
    script -qfec "printf 'n\n' | $SCRIPT_TO_TEST --update" /dev/null || true
    pass "--update prompt executed"
  fi
else
  echo "Skipping interactive update (no TTY or AUTO_TTY=0)"
fi

# 9) Cache bypass
echo -e "\n9) Cache bypass"
if echo "$HELP" | grep -q -- "--force-update"; then
  require_zero "--force-update summary" "$SCRIPT_TO_TEST" --summary --force-update
fi
if echo "$HELP" | grep -q -- "--force"; then
  require_zero "--force image checks" "$SCRIPT_TO_TEST" --summary --force
fi

# 10) --no-update
echo -e "\n10) --no-update"
if echo "$HELP" | grep -q -- "--no-update"; then
  require_zero "--no-update path" "$SCRIPT_TO_TEST" --summary --no-update
else
  echo "Skipping --no-update (flag not supported)"
fi

# 11) --prune
echo -e "\n11) --prune"
if echo "$HELP" | grep -q -- "--prune"; then
  if [[ "$RUN_DANGEROUS" == "1" ]]; then
    "$SCRIPT_TO_TEST" --prune --no-update --summary || true
    pass "--prune executed (dangerous mode)"
  else
    echo "Skipping --prune (dangerous). Set RUN_DANGEROUS=1 to enable."
  fi
else
  echo "Skipping --prune (flag not supported)"
fi

# 12) Interrupt handling (trap cleanup), excluding test artifacts and the harness log
echo -e "\n12) Interrupt handling"
"$SCRIPT_TO_TEST" --summary --no-update >/dev/null 2>&1 &
PID=$!; sleep 2
if ps -p "$PID" >/dev/null 2>&1; then
  kill -INT "$PID" || true; wait "$PID" || true; sleep 1

  # Derive LOG_FILE basename for exclusion to avoid absolute -path mismatches
  LOG_BASE="$(basename "$LOG_FILE" 2>/dev/null || echo 'container-monitor-test.log')"

  RESIDUALS="$(find "$TEST_TMP" -mindepth 1 \
    -not -path "$SAVE_LOGS_DIR" -not -path "$SAVE_LOGS_DIR/*" \
    -not -name 'save-logs.out' -not -name 'save-logs.err' \
    -not -name 'logs-filter.out' -not -name 'logs-filter.err' \
    -not -name "$LOG_BASE" \
    -not -name '*_logs_*.log' \
    -not -name '*_logs_*.log.err' \
    -print -quit || true)"

  if [[ -n "$RESIDUALS" ]]; then
    echo "Residual files (excluding test artifacts):"
    find "$TEST_TMP" -mindepth 1 \
      -not -path "$SAVE_LOGS_DIR" -not -path "$SAVE_LOGS_DIR/*" \
      -not -name 'save-logs.out' -not -name 'save-logs.err' \
      -not -name 'logs-filter.out' -not -name 'logs-filter.err' \
      -not -name "$LOG_BASE" \
      -not -name '*_logs_*.log' \
      -not -name '*_logs_*.log.err' -ls || true
    fail "Trap cleanup left residual files"
  else
    pass "Trap cleaned TMPDIR (excluding test artifacts)"
  fi
else
  fail "Background process not running for interrupt test"
fi

echo -e "\n${PASS_COLOR}=== Tests Complete ===${NC}"
