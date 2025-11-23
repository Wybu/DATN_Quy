#!/bin/bash
# Script test thực tế - trigger events và kiểm tra xem có được bắt không

DETECTOR_DIR="$(cd "$(dirname "$0")" && pwd)"
CSV_FILE="$DETECTOR_DIR/log.csv"
CSV_ALL_FILE="$DETECTOR_DIR/log_all.csv"
OUTPUT_FILE="$DETECTOR_DIR/detector_output.txt"
TEST_DIR="/tmp/detector_test_$$"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "TEST REAL EVENT DETECTION"
echo "=========================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "${RED}Error: Must run as root (sudo)${NC}"
    exit 1
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$DETECTOR_PID" ]; then
        kill $DETECTOR_PID 2>/dev/null
        wait $DETECTOR_PID 2>/dev/null
    fi
    rm -rf "$TEST_DIR" 2>/dev/null
    echo "Done."
}

trap cleanup EXIT

# Remove old files
rm -f "$CSV_FILE" "$CSV_ALL_FILE" "$OUTPUT_FILE"

# Start detector
echo "${YELLOW}Starting detector...${NC}"
cd "$DETECTOR_DIR"
python3 detector.py > "$OUTPUT_FILE" 2>&1 &
DETECTOR_PID=$!
sleep 5

if ! kill -0 $DETECTOR_PID 2>/dev/null; then
    echo "${RED}Error: Detector failed to start${NC}"
    cat "$OUTPUT_FILE"
    exit 1
fi

echo "${GREEN}Detector started (PID: $DETECTOR_PID)${NC}"
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Function to check event in CSV
check_csv() {
    local event_type=$1
    local event_name=$2
    local use_all_csv=$3  # "true" to check log_all.csv, "false" for log.csv
    local csv_to_check
    if [ "$use_all_csv" = "true" ]; then
        csv_to_check="$CSV_ALL_FILE"
    else
        csv_to_check="$CSV_FILE"
    fi
    
    local count=0
    if [ -f "$csv_to_check" ]; then
        # Use awk to count, ensure output is a single number
        count=$(awk -F',' "NR>1 && \$3==$event_type {count++} END {if (count) print count; else print 0}" "$csv_to_check" 2>/dev/null | head -1)
    fi
    # Ensure count is a valid number
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        count=0
    fi
    
    local file_name=$(basename "$csv_to_check")
    if [ "$count" -gt 0 ]; then
        echo "  ${GREEN}✅ $file_name: Found $count $event_name events (Type $event_type)${NC}"
        return 0
    else
        echo "  ${RED}❌ $file_name: NO $event_name events found (Type $event_type)${NC}"
        return 1
    fi
}

# Function to check event in terminal output
check_terminal() {
    local pattern=$1
    local event_name=$2
    local should_emit=$3
    local count=0
    if [ -f "$OUTPUT_FILE" ]; then
        count=$(grep -c "$pattern" "$OUTPUT_FILE" 2>/dev/null || echo 0)
    fi
    # Ensure count is a valid number
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        count=0
    fi
    
    if [ "$count" -gt 0 ]; then
        echo "  ${GREEN}✅ Terminal: Found '$pattern' $count times${NC}"
        return 0
    else
        if [ "$should_emit" = "true" ]; then
            echo "  ${RED}❌ Terminal: '$pattern' NOT FOUND (should emit!)${NC}"
            return 1
        else
            echo "  ${YELLOW}⚠️  Terminal: '$pattern' not found (expected - emit_always=false)${NC}"
            return 0
        fi
    fi
}

# Test results
PASSED=0
FAILED=0

echo "=========================================="
echo "Test 1: T_DELETE (Type 2)"
echo "=========================================="
echo "Triggering delete operations..."
echo "test" > "$TEST_DIR/delete1.txt"
echo "test" > "$TEST_DIR/delete2.txt"
echo "test" > "$TEST_DIR/delete3.txt"
rm -f "$TEST_DIR/delete1.txt" "$TEST_DIR/delete2.txt" "$TEST_DIR/delete3.txt" 2>/dev/null
sleep 3
# DELETE should be in both log.csv and log_all.csv (emit_always=true)
# Check log_all.csv first (all events)
if check_csv 2 "DELETE" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
# Then check log.csv (filtered events)
if check_csv 2 "DELETE" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Del" "DELETE" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "Test 2: T_ENCRYPT (Type 3)"
echo "=========================================="
echo "Triggering encryption operations using simulator..."
# Use the project's simulator to trigger encryption
SIMULATOR_DIR="$DETECTOR_DIR/../simulator"
ENCRYPT_TEST_DIR="$TEST_DIR/encrypt_test"
mkdir -p "$ENCRYPT_TEST_DIR"
# Create some test files to encrypt
for i in {1..5}; do
    echo "test data $i" > "$ENCRYPT_TEST_DIR/file_$i.txt"
done

# Try to run simulator if available
if [ -f "$SIMULATOR_DIR/simulator.py" ]; then
    # Check if pyAesCrypt is available
    if python3 -c "import pyAesCrypt" 2>/dev/null; then
        echo "Running simulator to encrypt files..."
        cd "$SIMULATOR_DIR"
        # Run with timeout to prevent hanging
        timeout 5 python3 simulator.py --dir "$ENCRYPT_TEST_DIR" --mode encrypt --password "test123" 2>/dev/null || true
        cd - > /dev/null
    else
        echo "pyAesCrypt not available, trying openssl command (with timeout)..."
        # Fallback to openssl command with timeout
        timeout 2 openssl enc -aes-256-cbc -in /dev/zero -out /dev/null -pass pass:test 2>/dev/null || true
    fi
else
    echo "Simulator not found, trying openssl command (with timeout)..."
    timeout 2 openssl enc -aes-256-cbc -in /dev/zero -out /dev/null -pass pass:test 2>/dev/null || true
fi
sleep 2
# ENCRYPT should be in both log.csv and log_all.csv (emit_always=true)
if check_csv 3 "ENCRYPT" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Enc" "ENCRYPT" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "Test 3: T_READ (Type 4)"
echo "=========================================="
echo "Triggering read operations..."
cat /etc/passwd > /dev/null 2>&1
head -100 /proc/meminfo > /dev/null 2>&1
dd if=/dev/zero bs=1024 count=10 2>/dev/null | cat > /dev/null
sleep 2
# Check log_all.csv (should have all events)
if check_csv 4 "READ" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Read" "READ" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "Test 4: T_WRITE (Type 5)"
echo "=========================================="
echo "Triggering write operations..."
echo "test data" > "$TEST_DIR/test1.txt"
dd if=/dev/zero of="$TEST_DIR/test2.bin" bs=1024 count=10 2>/dev/null
python3 -c "with open('$TEST_DIR/test3.txt', 'w') as f: f.write('data' * 1000)" 2>/dev/null
sleep 2
# Check log_all.csv (should have all events)
if check_csv 5 "WRITE" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Writ" "WRITE" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "Test 5: T_SCAN (Type 6)"
echo "=========================================="
echo "Triggering directory scanning..."
for i in {1..20}; do touch "$TEST_DIR/file_$i.txt"; done
ls -la "$TEST_DIR" > /dev/null 2>&1
find "$TEST_DIR" -type f > /dev/null 2>&1
python3 -c "import os; os.listdir('$TEST_DIR')" 2>/dev/null
sleep 2
# Check log_all.csv (should have all events)
if check_csv 6 "SCAN" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Scan" "SCAN" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "Test 6: T_RENAME (Type 7)"
echo "=========================================="
echo "Triggering rename operations..."
echo "original" > "$TEST_DIR/original.txt"
mv "$TEST_DIR/original.txt" "$TEST_DIR/renamed.txt"
mv "$TEST_DIR/renamed.txt" "$TEST_DIR/final.txt"
sleep 2
# RENAME should be in both log.csv and log_all.csv (emit_always=true)
if check_csv 7 "RENAME" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Ren" "RENAME" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "Test 7: T_NET_SOCKET (Type 8)"
echo "=========================================="
echo "Triggering socket creation..."
python3 -c "
import socket
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s1.close()
s2.close()
" 2>/dev/null
sleep 2
# Check log_all.csv (should have all events)
if check_csv 8 "NET_SOCKET" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Sock" "NET_SOCKET" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "Test 8: T_NET_CONNECT (Type 9)"
echo "=========================================="
echo "Triggering network connections..."
python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    s.connect(('8.8.8.8', 53))
    s.close()
except:
    pass
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    s.connect(('1.1.1.1', 80))
    s.close()
except:
    pass
" 2>/dev/null
sleep 2
# Check log_all.csv (should have all events)
if check_csv 9 "NET_CONNECT" "true"; then
    ((PASSED++))
else
    ((FAILED++))
fi
if check_terminal "Conn" "NET_CONNECT" "false"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# Stop detector
echo "Stopping detector..."
kill $DETECTOR_PID 2>/dev/null
wait $DETECTOR_PID 2>/dev/null
sleep 1

# Final summary
echo ""
echo "=========================================="
echo "FINAL RESULTS"
echo "=========================================="
echo "Passed: ${GREEN}$PASSED${NC}"
echo "Failed: ${RED}$FAILED${NC}"
echo ""

if [ -f "$CSV_FILE" ]; then
    echo "log.csv (filtered events):"
    echo "Event distribution:"
    awk -F',' 'NR>1 {count[$3]++} END {
        types[0]="OPEN"; types[1]="CREATE"; types[2]="DELETE"; types[3]="ENCRYPT";
        types[4]="READ"; types[5]="WRITE"; types[6]="SCAN"; types[7]="RENAME";
        types[8]="NET_SOCKET"; types[9]="NET_CONNECT";
        for (i=0; i<=9; i++) {
            name = types[i]
            cnt = count[i] ? count[i] : 0
            if (cnt > 0) {
                printf "  Type %d (%s): %d events\n", i, name, cnt
            }
        }
    }' "$CSV_FILE"
    echo ""
fi

if [ -f "$CSV_ALL_FILE" ]; then
    echo "log_all.csv (ALL events):"
    echo "Event distribution:"
    awk -F',' 'NR>1 {count[$3]++} END {
        types[0]="OPEN"; types[1]="CREATE"; types[2]="DELETE"; types[3]="ENCRYPT";
        types[4]="READ"; types[5]="WRITE"; types[6]="SCAN"; types[7]="RENAME";
        types[8]="NET_SOCKET"; types[9]="NET_CONNECT";
        for (i=0; i<=9; i++) {
            name = types[i]
            cnt = count[i] ? count[i] : 0
            if (cnt > 0) {
                printf "  Type %d (%s): %d events\n", i, name, cnt
            }
        }
    }' "$CSV_ALL_FILE"
else
    echo "${RED}log_all.csv file not found!${NC}"
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo "${RED}❌ Some tests failed!${NC}"
    exit 1
fi

