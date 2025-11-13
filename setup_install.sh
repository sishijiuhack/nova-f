#!/bin/bash
# test uv installation
if ! command -v uv &> /dev/null
then
    echo "uv could not be found, installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi

if [ -f .venv ] ; then
    echo "Virtual environment already exists."

else
    uv python install 3.12
    uv venv
    uv pip install -r ./pyproject.toml
fi
source .venv/bin/activate
