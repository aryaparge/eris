"""
Prepare the dashboard after a training run:
  1. reference.json     - the training-split frame patterns (same split as eris_t5.py),
                          used for counterfactuals, prototypes and CAN-ID knowledge
  2. explain_global.json - explanations for every held-out test frame

Usage: python scripts/precompute.py --data data [--run results_live]
"""
import argparse, json, os, random, sys
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))

p = argparse.ArgumentParser()
p.add_argument("--data", default=os.path.join(ROOT, "data"))
p.add_argument("--run", default=os.path.join(ROOT, "results_live"))
args = p.parse_args()
SEED = 42
FILES = {
    "BENIGN": "hexadecimal_benign.csv",
    "DoS": "hexadecimal_DoS.csv",
    "GAS": "hexadecimal_spoofing-GAS.csv",
    "RPM": "hexadecimal_spoofing-RPM.csv",
    "SPEED": "hexadecimal_spoofing-SPEED.csv",
    "STEERING_WHEEL": "hexadecimal_spoofing-STEERING_WHEEL.csv",
}
DATA_COLS = [f"DATA_{i}" for i in range(8)]


# ---------------------------------------------------------------- same as eris_t5.py steps 1-2
def norm_byte(v):
    return "%02X" % int(str(v).replace(".0", ""), 16)


pats_by_cls = {}
for cls, fn in FILES.items():
    df = pd.read_csv(os.path.join(args.data, fn), dtype=str, keep_default_na=False,
                     usecols=["ID"] + DATA_COLS).drop_duplicates()
    df["ID"] = df["ID"].map(lambda v: "%03X" % int(v, 16))
    for c in DATA_COLS:
        df[c] = df[c].map(norm_byte)
    utr = "CAN_ID " + df["ID"]
    for i, c in enumerate(DATA_COLS):
        utr = utr + f" D{i} " + df[c]
    pats_by_cls[cls] = sorted(set(utr))

train = []
for cls in sorted(pats_by_cls):  # groupby order in eris_t5.py
    pats = list(pats_by_cls[cls])
    random.Random(SEED).shuffle(pats)
    n = len(pats)
    if n >= 3:
        n_te = max(1, round(0.15 * n)); n_va = max(1, round(0.15 * n))
    elif n == 2:
        n_te, n_va = 1, 0
    else:
        n_te, n_va = 0, 0
    train += [[u, cls] for u in pats[n_te + n_va:]]
    print(f"{cls:15s} patterns {n:5d}  train {n - n_te - n_va}")

os.makedirs(args.run, exist_ok=True)
json.dump({"source": "training split", "patterns": train}, open(os.path.join(args.run, "reference.json"), "w"))
test = os.path.join(args.run, "test_predictions.csv")
if os.path.exists(test):
    overlap = set(pd.read_csv(test)["utr"]) & {u for u, _ in train}
    print("train/test overlap:", len(overlap))
print("wrote reference.json with", len(train), "training patterns")

# ---------------------------------------------------------------- global explanations
model = os.path.join(args.run, "model")
if os.path.exists(os.path.join(model, "config.json")) and os.path.exists(test):
    from engine import Engine
    from explain import Reference, global_explanation
    eng = Engine(model)
    df = pd.read_csv(test).drop_duplicates("utr")
    g = global_explanation(eng, Reference(args.run), df["utr"].tolist(), df["true_class"].tolist())
    json.dump(g, open(os.path.join(args.run, "explain_global.json"), "w"), indent=1)
    print("wrote explain_global.json, mean consistency (attacks):", g["mean_consistency_attacks"])
