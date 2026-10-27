# ERIS — Explainable, Risk-aware IDS for the Internet of Vehicles

ERIS has three stages: a **T5 CAN-bus intrusion detector** (classification), an **explainability** stage that shows which identifier and payload bytes drove each decision, and a **risk-assessment** stage (preview) that rates the severity for the attacked vehicle function. An **analyst console** brings them together with live alerts and incident management. ERIS extends the LLM-based integrated IDS of Aishwarya et al. (2025).


## What it does

Each CAN frame from **CICIoV2024** is turned into a short text sequence (`CAN_ID 1DC D0 02 D1 3D …`). T5 then generates one of six labels: `BENIGN`, `DoS`, `GAS`, `RPM`, `SPEED`, `STEERING_WHEEL`.

## Evaluation design

1. **Leak-free split.** Train, validation and test are split by *unique frame pattern*, so no frame appears in more than one split. The model is chosen on validation loss only; the test set is never used for selection.
2. **No formatting leaks.** The raw CSVs give away the class through formatting. The DoS file has no DLC column, and spoofing files write bytes unpadded (`0`, `2.0`, `000001DC`). All IDs and bytes are normalised to fixed-width uppercase hex, and constant fields are dropped.
3. **Pattern-level metrics** are reported alongside row-level metrics, because the dataset is highly repetitive. For example, GAS has only 2 distinct frames.
4. **Reload check.** The saved model is reloaded from disk and must give identical predictions.

## Results (`results/`)

t5-small architecture trained from scratch (45M params, 5 epochs; best epoch by validation loss = 3). Test set: 1,800 rows from held-out patterns.

| Metric | Value |
|---|---|
| Row accuracy | 91.7% |
| Macro F1 | 0.912 |
| Pattern-level accuracy | 97.0% (32/33) |

Every class except RPM scores 1.00 F1. All errors come from one RPM frame (`CAN ID 201`, predicted SPEED 149 times). Its payload is byte-for-byte identical to a SPEED frame (`06 1C 06 3F 06 2A 02 29`), which looks like a dataset artefact.

Pattern split per class: BENIGN 3,547 · DoS 21 · RPM 10 · SPEED 5 · STEERING_WHEEL 3 · GAS 2 (see `results/pattern_split.csv`). Classes with 1–3 test patterns give fragile per-class scores.

## Run it

Download the six `hexadecimal_*.csv` files of [CICIoV2024](https://www.unb.ca/cic/datasets/iov-dataset-2024.html) (not included here) into `data/`.

```bash
uv venv --python 3.11 .venv && uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/python scripts/check_data.py data                          # verify the six files
.venv/bin/python eris_t5.py --data data --scratch --out results_live # same architecture, random init, hex tokenizer
.venv/bin/python eris_t5.py --data data --out results_pre            # pretrained t5-small (needs Hugging Face access)
```

`./train_live.sh` runs the scratch command and then `scripts/precompute.py`, which saves the training-split reference frames and the explanations the dashboard uses.

## Analyst console (`dashboard/`)

```bash
./run_demo.sh            # http://localhost:8000   (--reset clears alerts)
```

| Page | What it shows |
|---|---|
| Live Monitor | Held-out test frames replayed as live CAN traffic, classified in real time; attack injection; traffic and severity charts |
| Alerts | Triage queue: filter, search, bulk acknowledge/resolve, assign; each alert opens with its explanation, risk and audit trail |
| Incidents | Alerts grouped by class and CAN ID, with status workflow, notes and CSV/JSON export |
| Frame Inspector | Any raw frame → normalisation → tokens → prediction, explanation and risk |
| Explainability | Per-class global attribution, identifier-vs-payload reliance and per-frame explanations |
| Model Stats | Every evaluation output: metrics, loss curve, confusion matrix, per-class and pattern-level tables, prediction browser |
| System & Tests | Architecture, leak-free protocol and the Table 5.5 test cases run live |

**Explainability.** Each decision is explained with five views:
- occlusion of each field
- Integrated Gradients on the T5 input embeddings, with a completeness check
- decoder cross-attention
- a verified counterfactual built from benign traffic on the same CAN ID
- the nearest training prototype

These are combined into a plain-language rationale. **Risk** maps the class to the affected vehicle function and scores impact × feasibility (ISO/SAE 21434-style), adjusted for confidence and sustained attacks.

Tests: `.venv/bin/python -m pytest tests -q`. The demo runbook is in `DEMO.md`.

Or open `iovids.ipynb` in Google Colab (T4 GPU) and upload the CSVs to `/content`.

## Stack

PyTorch · Hugging Face Transformers / Datasets · scikit-learn · pandas · FastAPI · SQLite · Chart.js
