#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo " AI Cyber Threat Intelligence - Setup"
echo "============================================"
echo ""

# Create virtual environment (isolated from Anaconda/system Python)
if [ ! -d ".venv" ]; then
    echo "[1/4] Creating virtual environment (.venv) ..."
    python3 -m venv .venv
else
    echo "[1/4] Virtual environment already exists."
fi

# Activate it
echo "[2/4] Activating virtual environment ..."
source .venv/bin/activate

echo "  Python: $(which python)"
echo "  Version: $(python --version)"

# Install dependencies into venv
echo "[3/4] Installing dependencies ..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# Create config from example if not exists
if [ ! -f "config/settings.yaml" ]; then
    cp config/settings.example.yaml config/settings.yaml
    echo "  Created config/settings.yaml from template"
fi

# Create data directories
mkdir -p data/raw data/processed data/db logs

# Initialize database
echo "[4/4] Initializing database ..."
python -m src.main init

echo ""
echo "============================================"
echo " Setup Complete!"
echo "============================================"
echo ""
echo "IMPORTANT: Every time you open a new terminal,"
echo "you MUST activate the virtual environment first:"
echo ""
echo "  source .venv/bin/activate"
echo ""
echo "Then you can run:"
echo "  python -m src.main collect --all      # collect from all sources"
echo "  python -m src.main collect -s arxiv   # collect from one source"
echo "  python -m src.main status             # show statistics"
echo "  python -m src.main sources            # list available sources"
echo ""
