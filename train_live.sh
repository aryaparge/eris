#!/usr/bin/env bash
# Re-run the reported pipeline (report Ch. 6.1) and prepare the dashboard for it.
#   ./train_live.sh            # scratch mode, as in the report
set -eo pipefail
cd "$(dirname "$0")"
.venv/bin/python scripts/check_data.py data
mkdir -p results_live
.venv/bin/python eris_t5.py --data data --scratch --out results_live 2>&1 | grep -v -i warning | tee results_live/train_log.txt
.venv/bin/python scripts/precompute.py --data data --run results_live
echo "done - restart ./run_demo.sh to use results_live/model"
