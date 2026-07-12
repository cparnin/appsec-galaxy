#!/bin/bash
# Simple test runner

echo "🧪 Running tests..."

# Run tests
.venv/bin/python -m pytest tests/test_appsec_galaxy.py -v

# Check exit code
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Tests passed!"
else
    echo "❌ Tests failed"
fi

exit "$TEST_EXIT_CODE"
