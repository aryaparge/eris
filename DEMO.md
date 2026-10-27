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

| # | Page | Do | Say |
|---|------|----|-----|
| 1 | **Live Monitor** | Point at the ticker and the traffic chart. Click **Steering spoofing** under "Inject". | "ERIS replays the held-out test frames of CICIoV2024 as live CAN traffic. None of these frames were seen in training. Every frame goes through classification, then explanation, then risk." A toast appears: "New Critical incident". |
| 2 | **Alerts** | Click a Critical alert. | The analyst queue: severity, class, CAN ID, confidence and status. |
| 3 | Alert drawer | Scroll through it. | **Explanation (our contribution):** the frame heatmap shows which bytes drove the decision, followed by the rationale in plain language. Four methods are shown side by side (occlusion, Integrated Gradients, cross-attention, counterfactual), plus the method-agreement score and the IG completeness check. Then **Risk**: the affected vehicle function, impact × feasibility (ISO/SAE 21434), and recommended actions. |
| 4 | Alert drawer | Click **Acknowledge**, type an assignee, then **Assign**. Add a note. | The audit trail records who did what and when. MTTA updates on the Live Monitor. |
| 5 | **Incidents** | Open the incident and click **Resolve**. Then click **Export CSV**. | Repeated frames are grouped into one incident, so the analyst isn't flooded. The export produces an incident report. |
| 6 | **Frame Inspector** | Click **Analyse** on the default raw values `000001DC`, `2.0`, `3`. | This shows the formatting-leak fix live: the green values were normalised, and the frame is shown as a UTR and as tokens. |
| 7 | Frame Inspector | Click the **RPM (error case)** preset. | This is the single error from Section 7.4. Point to the "Identifier vs payload" card: with the CAN ID hidden ERIS still says SPEED, but with the payload hidden it says RPM. So the SPEED-identical payload causes the error, which confirms Section 7.4 with evidence. CAN ID 201 is shared by RPM, GAS and SPEED in training, so the ID alone is ambiguous. |
| 8 | **Explainability** | Show the "What decides attack frames" tile and the global heatmap. | Across the 8 held-out attack frames, the payload decides 3, the identifier decides 2, either one alone suffices for 2, and 1 needs both. The model relies heavily on CAN IDs, the exact shortcut risk raised in Limitations (Section 7.6). Explainability is how ERIS makes this visible to the analyst. |
| 9 | **Model Stats** | Scroll down the page. | These are all the numbers from Chapter 7, so nobody has to read terminal output: 91.72% row accuracy, macro F1 0.9118, 32/33 patterns, and the reload check. Toggle **Live re-run** to show the run reproduced on this laptop. |
| 10 | **System & Tests** | Click **▶ Run checks**. | Table 5.5 executed live against the running system. |

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
