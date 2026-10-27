"""
Check that the six CICIoV2024 hexadecimal CSVs are in place before training.

Usage: python scripts/check_data.py [data]
"""
import os, sys
import pandas as pd

FILES = {
    "BENIGN": "hexadecimal_benign.csv",
    "DoS": "hexadecimal_DoS.csv",
    "GAS": "hexadecimal_spoofing-GAS.csv",
    "RPM": "hexadecimal_spoofing-RPM.csv",
    "SPEED": "hexadecimal_spoofing-SPEED.csv",
    "STEERING_WHEEL": "hexadecimal_spoofing-STEERING_WHEEL.csv",
}
REPORTED = {"BENIGN": 1223737, "DoS": 74663, "RPM": 54900, "SPEED": 24951,
            "STEERING_WHEEL": 19977, "GAS": 9991}  # Table 5.1
NEED = ["ID"] + [f"DATA_{i}" for i in range(8)]

d = sys.argv[1] if len(sys.argv) > 1 else "data"
present = os.listdir(d) if os.path.isdir(d) else []
ok = True
for cls, fn in FILES.items():
    path = os.path.join(d, fn)
    if not os.path.exists(path):
        alt = [f for f in present if f.lower().replace("_", "-") == fn.lower().replace("_", "-")]
        print(f"MISSING  {fn}" + (f"   (found '{alt[0]}' - rename it)" if alt else ""))
        ok = False
        continue
    cols = list(pd.read_csv(path, nrows=0, dtype=str).columns)
    miss = [c for c in NEED if c not in cols]
    n = sum(1 for _ in open(path)) - 1
    flag = "" if n == REPORTED[cls] else f"   (report: {REPORTED[cls]:,})"
    print(f"{'OK' if not miss else 'BADCOLS'}  {fn:44s} {n:>10,} rows  cols={cols}{flag}")
    ok &= not miss
print("\nall six files ready" if ok else "\nfix the files above before running eris_t5.py")
sys.exit(0 if ok else 1)
