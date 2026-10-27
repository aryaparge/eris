"""
Run the trained ERIS model from the terminal.

  python scripts/predict.py --test                       # all 33 held-out test frames
  python scripts/predict.py --id 000001DC --data 2.0 1E F5 3 0 0 0 0
  python scripts/predict.py --utr "CAN_ID 158 D0 06 D1 1C D2 06 D3 3F D4 06 D5 2A D6 02 D7 29" --explain
"""
import argparse, os, sys, warnings

warnings.filterwarnings("ignore")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import pandas as pd  # noqa: E402
import engine as E  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument("--model", default=None, help="model folder (default: results_live/model)")
p.add_argument("--utr", help="frame as text: 'CAN_ID 1DC D0 02 ... D7 00'")
p.add_argument("--id", help="raw CAN ID, e.g. 000001DC")
p.add_argument("--data", nargs=8, help="8 raw data bytes, e.g. 2.0 1E F5 3 0 0 0 0")
p.add_argument("--test", action="store_true", help="classify every unique held-out test frame")
p.add_argument("--explain", action="store_true", help="also print the explanation")
args = p.parse_args()

model_dir = args.model or E.find_model_dir()
if not model_dir:
    sys.exit("no trained model found - run ./train_live.sh first")
eng = E.Engine(model_dir)
print(f"model: {os.path.relpath(model_dir, ROOT)}  ({eng.params / 1e6:.2f}M params, vocab {eng.vocab})\n")


def show(utr, true=None):
    r = eng.classify_one(utr)
    mark = "" if true is None else ("  OK" if r["label"] == true else f"  WRONG (true {true})")
    print(f"{utr}  ->  {r['label']:<15s} {r['confidence']:7.2%}{mark}")
    return r


if args.test:
    run = os.path.dirname(model_dir)
    df = pd.read_csv(os.path.join(run, "test_predictions.csv"))
    pats = df.drop_duplicates("utr")
    ok = sum(show(u, t)["label"] == t for u, t in zip(pats["utr"], pats["true_class"]))
    print(f"\npattern-level accuracy: {ok}/{len(pats)} = {ok / len(pats):.2%}")
    preds = {u: eng.classify_one(u)["label"] for u in pats["utr"]}
    rows = (df["utr"].map(preds) == df["true_class"]).mean()
    print(f"row-level accuracy:     {rows:.2%} on {len(df):,} test rows")
else:
    if args.utr:
        utr = " ".join(args.utr.split())
        utr, steps = E.normalise_raw(E.field_values(utr)[0], E.field_values(utr)[1:])
    elif args.id and args.data:
        utr, steps = E.normalise_raw(args.id, args.data)
        print("normalisation: " + "  ".join(f"{s['raw']}->{s['normalised']}" for s in steps) + "\n")
    else:
        p.error("give --test, --utr, or --id with --data")
    r = show(utr)
    print("probabilities: " + "  ".join(f"{c} {v:.2%}" for c, v in r["probs"].items()))
    if args.explain:
        from explain import Reference, explain
        ex = explain(eng, Reference(eng.run_dir), utr)
        print("\nfield attribution: " + "  ".join(f"{f}={v:.0%}" for f, v in zip(E.FIELDS, ex["combined"])))
        print("\nexplanation:")
        for line in ex["rationale"]:
            print("  - " + line)
