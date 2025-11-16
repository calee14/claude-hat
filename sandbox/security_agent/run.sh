#!/bin/bash
# Quick start script for the security agent

echo "🤖 AI Security Testing Agent"
echo "=============================="
echo ""

# Check if target is running
TARGET=${TARGET_URL:-"http://localhost:3000"}
echo "Checking if target is running at $TARGET..."

if curl -s -o /dev/null -w "%{http_code}" "$TARGET" | grep -q "200\|301\|302\|401\|403"; then
    echo "✓ Target is reachable"
else
    echo "✗ Target is not reachable at $TARGET"
    echo ""
    echo "Make sure your vulnerable app is running:"
    echo "  cd .. && npm run dev"
    exit 1
fi

echo ""

# Check if API key is set
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "✗ ANTHROPIC_API_KEY not set"
    echo ""
    echo "Please set your API key:"
    echo "  export ANTHROPIC_API_KEY='your-key-here'"
    echo ""
    echo "Or create a .env file with:"
    echo "  ANTHROPIC_API_KEY=your-key-here"
    exit 1
fi

echo "✓ ANTHROPIC_API_KEY is set"
echo ""

# Install dependencies if needed
if ! python3 -c "import anthropic" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

echo "Starting security agent..."
echo ""

# Run the agent
python3 main.py "$@"
