#!/bin/bash
set -e

SCRIPT_TO_TEST="./container-monitor.sh"
PASS_COLOR='\033[0;32m'
FAIL_COLOR='\033[0;31m'
NC='\033[0m' # No Color

# Ensure the script exists and is executable
if [ ! -f "$SCRIPT_TO_TEST" ]; then
    echo -e "${FAIL_COLOR}❌ ERROR: Script not found at ${SCRIPT_TO_TEST}${NC}"
    exit 1
fi
chmod +x "$SCRIPT_TO_TEST"

echo "=== Container Monitor Test Suite ==="

# --- Test 1: Normal Monitoring ---
echo -e "\n1. Normal monitoring test (checking for 'Bad file descriptor' errors)..."
if "$SCRIPT_TO_TEST" 2>&1 | grep -i "bad file descriptor"; then
    echo -e "${FAIL_COLOR}❌ FAIL: 'Bad file descriptor' error found in normal mode.${NC}"
else
    echo -e "${PASS_COLOR}✅ PASS: No 'Bad file descriptor' errors.${NC}"
fi

# --- Test 2: Summary Mode ---
echo -e "\n2. Summary mode test (checking for 'Bad file descriptor' errors)..."
if "$SCRIPT_TO_TEST" --summary 2>&1 | grep -i "bad file descriptor"; then
    echo -e "${FAIL_COLOR}❌ FAIL: 'Bad file descriptor' error found in summary mode.${NC}"
else
    echo -e "${PASS_COLOR}✅ PASS: No 'Bad file descriptor' errors.${NC}"
fi

# --- Test 3: Cleanup Verification (Normal Exit) ---
echo -e "\n3. Cleanup verification (Normal Exit)..."
"$SCRIPT_TO_TEST" --summary > /dev/null 2>&1
# Check if any temp directories or lock files are left behind
if ls /tmp/tmp.* 2>/dev/null | grep -q .; then
    echo -e "${FAIL_COLOR}❌ FAIL: A temporary directory was left in /tmp${NC}"
    ls /tmp/tmp.*
elif [ -f ./.monitor_state.lock ]; then
    echo -e "${FAIL_COLOR}❌ FAIL: Lock file .monitor_state.lock was left behind.${NC}"
else
    echo -e "${PASS_COLOR}✅ PASS: All temp files and locks were cleaned up.${NC}"
fi

# --- Test 4: Interrupt Handling (Trap Test) ---
echo -e "\n4. Interrupt handling test (Trap Test)..."
# We run without update checks to speed up the test
"$SCRIPT_TO_TEST" --no-update &
PID=$!
# Give it a few seconds to create the lock and temp dir
sleep 3
echo "Sending INT signal to PID $PID..."
kill -INT $PID
wait $PID 2>/dev/null
sleep 1 # Give the filesystem a moment to catch up

# Check if the trap successfully cleaned up the files
if ls /tmp/tmp.* 2>/dev/null | grep -q .; then
    echo -e "${FAIL_COLOR}❌ FAIL: A temporary directory was left in /tmp after interrupt.${NC}"
    ls /tmp/tmp.*
elif [ -f ./.monitor_state.lock ]; then
    echo -e "${FAIL_COLOR}❌ FAIL: Lock file .monitor_state.lock was left behind after interrupt.${NC}"
else
    echo -e "${PASS_COLOR}✅ PASS: All temp files and locks were cleaned up by the trap.${NC}"
fi

echo -e "\n${PASS_COLOR}=== Tests Complete ===${NC}"
