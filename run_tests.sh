#!/bin/bash
# Simple test runner

echo "🧪 Running tests..."

# Run the whole suite, matching the CI gate. Naming a single file here used
# to silently skip tests/test_ai_provider.py and tests/test_ai_consumers.py.
PYTHON_DOTENV_DISABLED=1 .venv/bin/python -m pytest tests/ -v

# Check exit code
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Tests passed!"
else
    echo "❌ Tests failed"
fi

exit "$TEST_EXIT_CODE"
