#!/bin/bash
# AppSec Galaxy - CLI Mode Launcher
# Auto-manages virtualenv and dependencies

set -euo pipefail

echo "🔒 AppSec Galaxy - CLI Mode"
echo "=================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Select a supported Python interpreter (3.11-3.13, matching CI)
echo "🔍 Checking prerequisites..."

SUPPORTED_PYTHONS=(python3.13 python3.12 python3.11 python3)
PYTHON_CMD=""

for candidate in "${SUPPORTED_PYTHONS[@]}"; do
    if command_exists "$candidate"; then
        if "$candidate" - <<'PY'
import sys
sys.exit(0 if (sys.version_info.major == 3 and 11 <= sys.version_info.minor <= 13) else 1)
PY
        then
            PYTHON_CMD="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ No supported Python interpreter found. Install Python 3.11 or 3.12 and retry."
    exit 1
fi

echo "✅ Using Python interpreter: $PYTHON_CMD ($($PYTHON_CMD --version | head -n1))"

# Ensure existing virtualenv uses a compatible interpreter
if [ -d ".venv" ] && [ -x ".venv/bin/python" ]; then
    if ! .venv/bin/python - <<'PY'
import sys
sys.exit(0 if (sys.version_info.major == 3 and 11 <= sys.version_info.minor <= 13) else 1)
PY
    then
        echo "⚠️  Existing .venv uses unsupported Python $(.venv/bin/python -c 'import sys; print(sys.version.split()[0])'). Recreating..."
        rm -rf .venv
    fi
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found. You'll need to add your API key for auto-remediation:"
    echo "   cp env.example .env"
    echo "   # Then edit .env to add OPENAI_API_KEY"
    echo ""
fi

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    $PYTHON_CMD -m venv .venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment found"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source .venv/bin/activate

# Check and install dependencies
echo "📋 Ensuring Python dependencies are installed..."

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --upgrade -e .
.venv/bin/python -c "import appsec_galaxy"

echo "✅ Python dependencies ready"

# Validate external scanners (Gitleaks/Trivy) are available
missing_tools=()
command_exists gitleaks || missing_tools+=("gitleaks")
command_exists trivy || missing_tools+=("trivy")

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "⚠️  Missing required CLI tools: ${missing_tools[*]}"
    echo "    Install them before running scans (see README)."
    echo ""
fi

# Check for code quality linters (optional but recommended)
echo "📊 Checking code quality linters (optional)..."
available_linters=()
missing_linters=()

# JavaScript/TypeScript - ESLint
if command_exists eslint; then
    available_linters+=("ESLint")
else
    missing_linters+=("eslint")
fi

# Python - Pylint (auto-install to venv)
if ! .venv/bin/python -c "import pylint" 2>/dev/null; then
    echo "   📦 Installing Pylint for Python code quality..."
    if .venv/bin/python -m pip install pylint 2>&1 | grep -q "Successfully installed\|Requirement already satisfied"; then
        echo "   ✅ Pylint installed successfully"
        available_linters+=("Pylint")
    else
        echo "   ⚠️  Pylint installation failed - Python code quality scanning disabled"
        missing_linters+=("pylint")
    fi
else
    available_linters+=("Pylint")
fi

# Java - Checkstyle
if command_exists checkstyle || [ -n "$(find /usr/local -name 'checkstyle*.jar' 2>/dev/null | head -1)" ]; then
    available_linters+=("Checkstyle")
else
    missing_linters+=("checkstyle")
fi

# Go - golangci-lint
if command_exists golangci-lint; then
    available_linters+=("golangci-lint")
else
    missing_linters+=("golangci-lint")
fi

# Show what's available
if [ ${#available_linters[@]} -gt 0 ]; then
    echo "   ✅ Available: ${available_linters[*]}"
fi

# Show what's missing
if [ ${#missing_linters[@]} -gt 0 ]; then
    echo "   ⚠️  Missing (optional): ${missing_linters[*]}"
    echo "   💡 Install commands:"
    [[ " ${missing_linters[*]} " =~ " eslint " ]] && echo "      npm install -g eslint"
    [[ " ${missing_linters[*]} " =~ " checkstyle " ]] && echo "      brew install checkstyle  # macOS"
    [[ " ${missing_linters[*]} " =~ " golangci-lint " ]] && echo "      brew install golangci-lint  # macOS"
fi

echo ""

# Display startup information
echo ""
echo "✨ Features:"
echo "   📁 Interactive repository selection"
echo "   🎯 Severity level selection (Critical/High or All)"
echo "   🔍 SAST, Secrets, and Dependency scanning"
echo "   🤖 AI-powered auto-remediation with PR creation"
echo "   📊 HTML reports with business impact analysis"
echo "   📋 SBOM generation (CycloneDX & SPDX)"
echo ""
echo "🚀 Starting AppSec Galaxy CLI..."
echo ""

# Launch CLI
python -m appsec_galaxy.main
