#!/bin/bash
set -e

echo "=== Integration Test Runner ==="
echo ""

# Build the release binary
echo "Building release binary..."
cargo build --release

# Stop any existing server
echo "Stopping existing server..."
lsof -ti:3000 | xargs kill -9 2>/dev/null || true
sleep 1

# Start the test server
echo "Starting test server..."
RUST_LOG=warn ./target/release/nostr-proxy > /tmp/integration_test_server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
echo "Waiting for server to be ready..."
sleep 3

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "❌ Server failed to start"
    cat /tmp/integration_test_server.log
    exit 1
fi

echo "✅ Server running (PID: $SERVER_PID)"
echo ""

# Run integration tests
echo "Running integration tests..."
cargo test --test integration_test -- --test-threads=1

TEST_EXIT_CODE=$?

# Cleanup
echo ""
echo "Stopping test server..."
kill $SERVER_PID 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "=== ✅ All integration tests passed ==="
else
    echo ""
    echo "=== ❌ Some integration tests failed ==="
    echo "Check server logs at /tmp/integration_test_server.log"
fi

exit $TEST_EXIT_CODE
