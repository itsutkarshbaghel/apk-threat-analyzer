#!/bin/bash
# Double-click this file on Mac to launch the APK Analyzer
cd "$(dirname "$0")"

echo "================================================"
echo "   APK Threat Analyzer - Starting..."
echo "================================================"

# Check Python
if ! command -v python3 &>/dev/null; then
    osascript -e 'display alert "Python3 not found" message "Please install Python from python.org" as critical'
    exit 1
fi

# Install streamlit if missing
python3 -c "import streamlit" 2>/dev/null || {
    echo "Installing Streamlit (one time only)..."
    pip3 install streamlit --break-system-packages --quiet 2>/dev/null || pip3 install streamlit --quiet
}

# Install jadx if missing (Mac)
if ! command -v jadx &>/dev/null; then
    if command -v brew &>/dev/null; then
        echo "Installing JADX (one time only)..."
        brew install jadx --quiet
    else
        echo "WARNING: JADX not found. Install from: https://github.com/skylot/jadx/releases"
    fi
fi

# Open browser after 3 seconds
(sleep 3 && open http://localhost:8502) &

echo ""
echo "Opening browser at http://localhost:8502 ..."
echo "Press Ctrl+C to stop."
echo ""

streamlit run app.py --server.port 8502 --browser.gatherUsageStats false
