# ERIS review demo: runbook

## Tonight (one time)

1. **Dataset.** Put the six CICIoV2024 *hexadecimal* CSVs in `data/`, then check them:
   ```bash
   .venv/bin/python scripts/check_data.py data
   ```
   Every line should say `OK`, and the row counts should match Table 5.1. If a file name differs (Kaggle mirrors sometimes rename files), rename it to the name the script prints.
2. **Train** (≈12 min on the M2; **already done on 27 Oct**, and the results reproduced the report exactly). This runs the exact Ch. 6.1 command, then precomputes the explanations:
   ```bash
   ./train_live.sh
   ```
   Check the end of `results_live/train_log.txt`. You should see `reloaded checkpoint gives identical predictions: True` and a test block close to Table 7.1. The split is deterministic, so `results_live/pattern_split.csv` must equal `results/pattern_split.csv`.
3. **Dry run.** Start the console, click through the talk track below once, then press **Reset alert database** on System & Tests.

## Before the examiners arrive

```bash
./run_demo.sh --reset
```
Open http://localhost:8000. The top bar should show **T5 · 45.24M params · results_live/model** with a green dot. It must **not** show "development model". Let the stream run for a minute so the charts fill.

Everything is local: no internet is needed, and Chart.js is vendored.

## Talk track (≈8 min)

The visible pages are Live Monitor, Alerts, Incidents and Model Stats. Inspector, Explainability and System & Tests are hidden in `HIDDEN` in `dashboard/static/app.js`. The printable version of this guide is `ERIS_Demo_Guide.pdf`.

| # | Page | Do | Say |
|---|------|----|-----|
| 1 | **Live Monitor** | Point at the ticker and the chart. | Held-out CICIoV2024 frames are replayed as live CAN traffic. Every frame goes through classification, then explanation, then risk. |
| 2 | Live Monitor | Click **Steering spoofing** under "Inject". | A "New Critical incident" pop-up appears. |
| 3 | **Alerts** | Click the top Critical alert. | The analyst queue: severity, class, CAN ID, confidence and status. |
| 4 | Alert drawer | Scroll through it. | **Explainability (our contribution):** the heatmap, the rationale, the Identifier vs payload card, the verified counterfactual, and the agreement/IG checks. Then the **Risk** card: the affected function, impact × feasibility and the recommended actions. |
| 5 | Alert drawer | Click **Acknowledged**, assign someone, add a note. | The audit trail records every action. |
| 6 | **Incidents** | Open the incident, click **Resolved**, then **Export CSV**. | Repeated frames become one incident, and the export is the incident report. |
| 7 | **Model Stats** | Scroll down, then switch to **Live re-run**. | All of Chapter 7: 91.72%, macro F1 0.9118, 32/33 patterns, reload check. The re-run on this laptop gave identical results. |
| 8 | Model Stats | In Error analysis, click **Explain this frame**. | With the CAN ID hidden the result is still SPEED; with the payload hidden it is RPM. The payload causes the Section 7.4 error. |

## Likely questions

- **"Is this live or canned?"** The model runs live. Every frame is classified by T5 at request time, and explanations are computed on demand. Use the Frame Inspector to type any frame.
- **"Why replay instead of a car?"** As the report states, the system works offline on recorded traffic (Section 1.3). The replay only uses held-out test patterns.
- **"Why 91.7% and not 99%?"** Results reported elsewhere are inflated by duplicated rows leaking across splits. ERIS uses a pattern-level split; see Table 7.4 on Model Stats.
- **"How do you know the explanation is faithful?"** Integrated Gradients satisfies completeness: the attributions sum to the change in log-probability, and the drawer shows that check. Occlusion and IG are independent methods, and their agreement (Spearman ρ) is reported. The counterfactual is verified: the edited frame is re-classified by the model.
- **"How is risk computed?"** ISO/SAE 21434-style impact × attack feasibility per vehicle function. It is downgraded for low confidence and escalated for sustained attacks.

## If something goes wrong

| Problem | Fix |
|---|---|
| Training not finished or failed | The dashboard falls back to `results/` (the reported numbers) and replays the recorded predictions. Model Stats still shows everything. |
| "development model" pill visible | `results_live/model` is missing. Run `./train_live.sh`, then restart `./run_demo.sh`. |
| Port 8000 busy | `PORT=8001 ./run_demo.sh` |
| Too many alerts on screen | System & Tests → **Reset alert database**, or `./run_demo.sh --reset` |
