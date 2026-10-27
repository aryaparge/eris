"""
ERIS explainability: why did the classifier label this frame the way it did?

Five complementary views, computed per frame and combined into one rationale:
  1. Occlusion       - mask each field (CAN_ID, D0..D7) with <unk>, measure the drop
                       in the predicted class log-probability.
  2. Integrated      - path integral of gradients from a fully masked frame to the
     Gradients         real frame on the encoder input embeddings (Sundararajan et al.);
                       attributions sum to f(frame) - f(masked frame).
  3. Attention       - decoder -> encoder cross-attention while the label is generated.
  4. Counterfactual  - smallest change, towards known benign traffic on the same CAN ID,
                       that makes ERIS call the frame BENIGN.
  5. Prototype       - nearest frame in the training reference set and its class.
"""
import json, os
from collections import defaultdict

import numpy as np
import pandas as pd
import torch

from engine import CLASSES, FIELDS, PRETTY, ROOT, field_values, utr_from_values

IG_STEPS = 32


# ---------------------------------------------------------------- reference knowledge
class Reference:
    """Known frames used for counterfactuals, prototypes and CAN-ID knowledge.

    Built from the training split by scripts/precompute.py (reference.json). Without the
    dataset it falls back to the frames in test_predictions.csv.
    """

    def __init__(self, run_dir):
        path = os.path.join(run_dir or "", "reference.json")
        if run_dir and os.path.exists(path):
            ref = json.load(open(path))
            pats, self.source = ref["patterns"], "training split"
        else:
            src = os.path.join(run_dir or "", "test_predictions.csv")
            if not os.path.exists(src):
                src = os.path.join(ROOT, "results", "test_predictions.csv")
            df = pd.read_csv(src).drop_duplicates("utr")
            pats, self.source = df[["utr", "true_class"]].values.tolist(), "held-out test frames"
        self.utrs = [u for u, _ in pats]
        self.cls = [c for _, c in pats]
        self.vals = np.array([field_values(u) for u in self.utrs])
        self.id_classes = defaultdict(lambda: defaultdict(int))
        for v, c in zip(self.vals, self.cls):
            self.id_classes[v[0]][c] += 1
        self.benign = self.vals[np.array(self.cls) == "BENIGN"]

    def nearest(self, vals, mask=None, k=1, exclude=None):
        pool = self.vals if mask is None else self.vals[mask]
        idx = np.arange(len(self.vals)) if mask is None else np.flatnonzero(mask)
        d = (pool != np.array(vals)).sum(1)
        if exclude is not None:
            d = np.where([self.utrs[i] == exclude for i in idx], 99, d)
        order = np.argsort(d, kind="stable")[:k]
        return [(int(idx[o]), int(d[o])) for o in order]


# ---------------------------------------------------------------- the five views
def occlusion(eng, utr, target):
    vals = field_values(utr)
    texts = [utr]
    for k in range(len(FIELDS)):
        v = list(vals); v[k] = eng.unk
        texts.append(utr_from_values(v))
    lp = np.log(np.clip(eng.probs(texts)[:, CLASSES.index(target)], 1e-12, 1))
    return (lp[0] - lp[1:]).tolist()  # same target as IG: log p(class)


def integrated_gradients(eng, utr, target, steps=IG_STEPS):
    vals = field_values(utr)
    masked = utr_from_values([eng.unk] * len(FIELDS))
    enc = eng.encode([utr, masked])
    ids, am = enc["input_ids"], enc["attention_mask"]
    t = CLASSES.index(target)
    with eng.lock:
        emb = eng.model.get_input_embeddings()
        with torch.no_grad():
            x, x0 = emb(ids[:1]), emb(ids[1:])
        alphas = (torch.arange(steps, dtype=torch.float32) + 0.5) / steps
        path = (x0 + alphas.view(-1, 1, 1) * (x - x0)).detach().requires_grad_(True)
        lp = eng.class_logprobs(am[:1].expand(steps, -1), inputs_embeds=path)[:, t]
        grads, = torch.autograd.grad(lp.sum(), path)
        attr = ((x - x0) * grads.mean(0, keepdim=True)).sum(-1)[0]
        with torch.no_grad():
            ends = eng.class_logprobs(am, inputs_embeds=torch.cat([x, x0]))[:, t]
    idx, _ = eng.field_token_index(utr)
    per_field = [float(attr[i].sum()) for i in idx]
    delta = float(ends[0] - ends[1])
    return per_field, {"target_delta": delta, "sum_attr": float(sum(per_field)),
                       "completeness_error": abs(delta - float(attr.sum()))}


def cross_attention(eng, utr, target):
    enc = eng.encode([utr])
    lab = eng.label_ids[CLASSES.index(target):CLASSES.index(target) + 1]
    with eng.lock, torch.no_grad():
        out = eng.model(**enc, decoder_input_ids=eng.model._shift_right(lab), output_attentions=True)
    att = torch.stack(out.cross_attentions).mean((0, 2))[0]  # layers, heads -> [tgt, src]
    real = (lab[0] != -100).sum()
    att = att[:real].mean(0)
    idx, _ = eng.field_token_index(utr)
    per_field = [float(att[i].sum()) for i in idx]
    return per_field, float(att.sum() - sum(per_field))  # rest = markers / EOS


def counterfactual(eng, ref, utr, label, order):
    if label == "BENIGN":
        return {"applicable": False}
    vals = field_values(utr)
    same_id = (ref.vals[:, 0] == vals[0]) & (np.array(ref.cls) == "BENIGN")
    scope = "benign frames on CAN ID " + vals[0]
    if not same_id.any():
        same_id = np.array(ref.cls) == "BENIGN"
        scope = "benign frames on any CAN ID (ID %s never appears in benign traffic)" % vals[0]
    near = ref.nearest(vals, same_id, k=5)
    if not near:
        return {"applicable": True, "found": False, "scope": scope}
    # one-field edits drawn from the nearest benign frames
    edits = []
    for i, _ in near:
        for k in range(len(FIELDS)):
            if ref.vals[i][k] != vals[k] and (k, ref.vals[i][k]) not in edits:
                edits.append((k, ref.vals[i][k]))
    texts = []
    for k, v in edits:
        nv = list(vals); nv[k] = v; texts.append(utr_from_values(nv))
    # greedy path to the nearest benign frame, most important field first
    target = ref.vals[near[0][0]]
    diff = [k for k in order if target[k] != vals[k]]
    paths, cur = [], list(vals)
    for k in diff:
        cur = list(cur); cur[k] = target[k]
        paths.append(utr_from_values(cur))
    p = eng.probs(texts + paths) if texts + paths else np.zeros((0, len(CLASSES)))
    b = CLASSES.index("BENIGN")
    hit = [(p[i, b], i) for i in range(len(texts)) if p[i].argmax() == b]
    if hit:
        _, i = max(hit)
        k, v = edits[i]
        changes, new = [k], texts[i]
        method = "single-field substitution from nearby benign traffic"
    else:
        j = next((j for j in range(len(paths)) if p[len(texts) + j].argmax() == b), None)
        if j is None:
            return {"applicable": True, "found": False, "scope": scope,
                    "reference": utr_from_values(list(target))}
        changes, new = sorted(diff[:j + 1]), paths[j]
        method = "greedy path to the nearest benign frame"
    pn = eng.probs([new])[0]
    nv = field_values(new)
    return {"applicable": True, "found": True, "method": method, "scope": scope,
            "changes": [{"field": FIELDS[k], "from": vals[k], "to": nv[k]} for k in changes],
            "frame": new, "new_label": "BENIGN", "new_confidence": float(pn[b]),
            "reference": utr_from_values(list(target))}


def prototype(ref, utr):
    vals = field_values(utr)
    (i, d), = ref.nearest(vals, k=1, exclude=utr)
    return {"frame": ref.utrs[i], "class": ref.cls[i], "distance": d,
            "diff_fields": [FIELDS[k] for k in range(len(FIELDS)) if ref.vals[i][k] != vals[k]],
            "source": ref.source}


# ---------------------------------------------------------------- combine
def _shares(x):
    a = np.abs(np.array(x, dtype=float))
    return (a / a.sum()).tolist() if a.sum() > 0 else [0.0] * len(a)


def _spearman(a, b):
    ra, rb = pd.Series(np.abs(a)).rank().values, pd.Series(np.abs(b)).rank().values
    if ra.std() == 0 or rb.std() == 0:
        return 0.0
    return float(np.corrcoef(ra, rb)[0, 1])


def _join(xs):
    return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]


def rationale(utr, label, conf, comb, cf, proto, ref, consistency):
    vals = field_values(utr)
    order = np.argsort(comb)[::-1]
    top, cum = [], 0.0
    for k in order:
        top.append(int(k)); cum += comb[k]
        if cum >= 0.6 or len(top) == 3:
            break
    id_share = comb[0]
    s = []
    s.append(f"ERIS classified this frame as {PRETTY[label]} with {conf:.1%} confidence.")
    names = [FIELDS[k] if k else "the CAN ID" for k in top]
    shown = [f"{FIELDS[k]}={vals[k]}" if k else f"ID {vals[0]}" for k in top]
    s.append(f"The decision rests mainly on {_join(names)} ({', '.join(shown)}), "
             f"which {'together carry' if len(top) > 1 else 'carries'} {cum:.0%} of the attribution.")
    if label != "BENIGN":
        if id_share >= 0.4:
            s.append(f"The identifier is the strongest single signal ({id_share:.0%}).")
        elif id_share < 0.15:
            s.append(f"The CAN ID contributes only {id_share:.0%}: the model is reading the payload, "
                     f"not the identifier.")
    seen = ref.id_classes.get(vals[0])
    if seen:
        parts = [f"{c} ({n} pattern{'s' if n > 1 else ''})"
                 for c, n in sorted(seen.items(), key=lambda x: -x[1])]
        s.append(f"In the {ref.source}, CAN ID {vals[0]} is used "
                 f"{'only ' if len(seen) == 1 else ''}by {_join(parts)}.")
    else:
        s.append(f"CAN ID {vals[0]} never appears in the {ref.source}.")
    if proto:
        art = "an" if proto["class"] == "RPM" else "a"
        s.append(f"The nearest known frame is {art} {proto['class']} frame differing in "
                 f"{proto['distance']} of 9 fields" +
                 (f" ({_join(proto['diff_fields'])})." if 0 < proto['distance'] <= 3 else "."))
    if cf.get("found"):
        ch = [f"{c['field']} from {c['from']} to {c['to']}" for c in cf["changes"]]
        s.append(f"Counterfactual: changing {_join(ch)} would make ERIS treat the frame as benign "
                 f"({cf['new_confidence']:.0%}).")
    elif cf.get("applicable"):
        s.append("No small change towards known benign traffic makes this frame look benign, "
                 "which indicates a strong attack signature.")
    s.append(f"Occlusion and Integrated Gradients {'agree' if consistency >= 0.6 else 'partly agree'} "
             f"on the field ranking (Spearman ρ = {consistency:.2f}).")
    return s


def explain(eng, ref, utr, label=None):
    cls = eng.classify_one(utr)
    label = label or cls["label"]
    occ = occlusion(eng, utr, label)
    ig, ig_check = integrated_gradients(eng, utr, label)
    att, att_rest = cross_attention(eng, utr, label)
    so, si = _shares(occ), _shares(ig)
    comb = ((np.array(so) + np.array(si)) / 2).tolist()
    order = list(np.argsort(comb)[::-1])
    cf = counterfactual(eng, ref, utr, label, order)
    proto = prototype(ref, utr)
    cons = _spearman(occ, ig)
    return {
        "utr": utr, "label": label, "confidence": cls["probs"][label], "probs": cls["probs"],
        "fields": FIELDS, "values": field_values(utr),
        "occlusion": occ, "occlusion_share": so,
        "integrated_gradients": ig, "ig_share": si, "ig_check": ig_check,
        "attention": att, "attention_share": _shares(att), "attention_markers": att_rest,
        "combined": comb, "consistency": cons,
        "id_share": comb[0], "payload_share": 1 - comb[0],
        "counterfactual": cf, "prototype": proto,
        "rationale": rationale(utr, label, cls["probs"][label], comb, cf, proto, ref, cons),
    }


def global_explanation(eng, ref, utrs, true_cls):
    """Mean combined attribution per predicted class over a set of frames."""
    rows = defaultdict(list)
    per_frame = []
    for u, t in zip(utrs, true_cls):
        e = explain(eng, ref, u)
        rows[e["label"]].append(e["combined"])
        per_frame.append({"utr": u, "true": t, "pred": e["label"], "combined": e["combined"],
                          "consistency": e["consistency"]})
    heat = {c: np.mean(rows[c], 0).tolist() for c in CLASSES if rows[c]}
    attacks = [f["consistency"] for f in per_frame if f["pred"] != "BENIGN"]
    return {"fields": FIELDS, "classes": [c for c in CLASSES if c in heat], "heatmap": heat,
            "frames": per_frame,
            "mean_consistency": float(np.mean([f["consistency"] for f in per_frame])),
            "mean_consistency_attacks": float(np.mean(attacks)) if attacks else None}
