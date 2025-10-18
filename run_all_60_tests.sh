#!/bin/bash

BASE_DIR="/home/sagar8022/0418/skp-major-project/TLS"

echo "============================="
echo " RUNNING 60 COMPLETE TESTS"
echo "============================="
echo ""

# Function to run tests for a specific level and mode
run_tests() {
    local level=$1
    local mode=$2
    local dir=$3
    
    echo ""
    echo "┌──────────────────────────────────┐"
    echo "│  $mode LEVEL $level (10 tests)     │"
    echo "└──────────────────────────────────┘"
    
    cd "$BASE_DIR/$dir"
    
    # Start server
    ./build/tls_server $level 1 >/dev/null 2>&1 &
    SERVER_PID=$!
    sleep 2
    
    # Run 10 client tests
    for i in {1..10}; do
        echo -n "  Test $i... "
        timeout 15 ./build/tls_client 127.0.0.1 4433 $level 1 >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "✓"
        else
            echo "✗"
        fi
        sleep 0.5
    done
    
    # Stop server
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    sleep 2
    
    # Check results
    CSV_FILE="$BASE_DIR/results/level${level}/same-machine/${mode}/client_metrics.csv"
    if [ -f "$CSV_FILE" ]; then
        COUNT=$(($(wc -l < "$CSV_FILE") - 1))
        echo "  📊 $COUNT/10 saved to CSV"
    else
        echo "  ⚠️  CSV file not found"
    fi
}

# Run all test combinations
run_tests 1 "classic" "classic-fork"
run_tests 1 "quantum" "quantum-fork"
run_tests 3 "classic" "classic-fork"
run_tests 3 "quantum" "quantum-fork"
run_tests 5 "classic" "classic-fork"
run_tests 5 "quantum" "quantum-fork"

echo ""
echo "============================="
echo " FINAL SUMMARY"
echo "============================="

for level in 1 3 5; do
    for mode in classic quantum; do
        CSV_FILE="$BASE_DIR/results/level${level}/same-machine/${mode}/client_metrics.csv"
        if [ -f "$CSV_FILE" ]; then
            COUNT=$(($(wc -l < "$CSV_FILE") - 1))
            echo "  Level $level $mode: $COUNT/10"
        else
            echo "  Level $level $mode: 0/10 (file not found)"
        fi
    done
done

echo "============================="
