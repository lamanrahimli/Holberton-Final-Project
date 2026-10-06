#!/usr/bin/env bash
# Developer / demo launcher on Linux or macOS.
#   bash scripts/run-dev.sh            -> validate rules + start the server (http://127.0.0.1:8080/)
#   bash scripts/run-dev.sh simulate   -> generate every synthetic scenario against the running server
#   bash scripts/run-dev.sh agent      -> start the agent with config/agent.yml
#   bash scripts/run-dev.sh tests      -> pytest
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -r requirements.txt
  .venv/bin/pip install --quiet -e .
fi
case "${1:-server}" in
  simulate) exec .venv/bin/kharibulbul simulate all ;;
  agent) exec .venv/bin/kharibulbul agent -c config/agent.yml ;;
  tests) exec .venv/bin/python -m pytest -q ;;
  *) .venv/bin/kharibulbul rules validate rules && exec .venv/bin/kharibulbul server -c config/server.yml ;;
esac
