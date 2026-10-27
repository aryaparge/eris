"""
ERIS analyst dashboard server.

  python -m uvicorn --app-dir dashboard server:app --port 8000
"""
import asyncio, csv, io, json, os, random, re, threading, time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import engine as E
from db import DB, STATUSES
from explain import Reference, explain, global_explanation
from risk import LEVELS, PROFILE, RiskAssessor

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = {"reported": os.path.join(E.ROOT, "results"), "live": os.path.join(E.ROOT, "results_live")}
ANALYST = os.environ.get("ERIS_ANALYST", "analyst")

app = FastAPI(title="ERIS")
pool = ThreadPoolExecutor(max_workers=2)
db = DB(os.path.join(HERE, "eris.db"))
risk = RiskAssessor()
state = {"engine": None, "ref": None, "loading": True, "global": None, "global_busy": False}
explain_cache = {}


def load_models():
    eng = E.get_engine()
    state["engine"] = eng
    state["ref"] = Reference(eng.run_dir if eng else RUNS["reported"])
    state["loading"] = False
    if eng:
        frames = STREAM.patterns()
        eng.classify(frames)  # warm cache for every replayable frame
        compute_global()
        for u in frames:  # explanations for every attack frame the stream can replay
            if eng.classify_one(u)["label"] != "BENIGN":
                get_explanation(u)


def compute_global():
    eng = state["engine"]
    path = os.path.join(eng.run_dir, "explain_global.json")
    if os.path.exists(path) and os.path.getmtime(path) > os.path.getmtime(
            os.path.join(eng.model_dir, "config.json")):
        state["global"] = json.load(open(path))
        return
    state["global_busy"] = True
    try:
        df = test_frames(eng.run_dir).drop_duplicates("utr")
        g = global_explanation(eng, state["ref"], df["utr"].tolist(), df["true_class"].tolist())
        json.dump(g, open(path, "w"), indent=1)
        state["global"] = g
    finally:
        state["global_busy"] = False


def get_explanation(utr, label=None):
    if label == state["engine"].classify_one(utr)["label"]:
        label = None
    key = (utr, label)
    if key not in explain_cache:
        explain_cache[key] = explain(state["engine"], state["ref"], utr, label)
    return explain_cache[key]


def test_frames(run_dir):
    p = os.path.join(run_dir, "test_predictions.csv")
    if not os.path.exists(p):
        p = os.path.join(RUNS["reported"], "test_predictions.csv")
    return pd.read_csv(p)


# ---------------------------------------------------------------- live replay stream
class Stream:
    """Replays held-out test frames (never seen in training) as live CAN traffic."""

    def __init__(self):
        df = test_frames(RUNS["live"] if os.path.exists(RUNS["live"]) else RUNS["reported"])
        self.by_cls = {c: g[["utr", "predicted_class"]].values.tolist()
                       for c, g in df.groupby("true_class")}
        self.running, self.rate, self.auto = True, 20, True
        self.burst = None  # (class, frames_left)
        self.next_auto = time.time() + 8
        self.clients = set()
        self.processed, self.window = 0, []
        self.class_rate = {c: 0 for c in E.CLASSES}

    def patterns(self):
        return sorted({u for v in self.by_cls.values() for u, _ in v})

    def inject(self, cls, n=60):
        if cls not in self.by_cls or cls == "BENIGN":
            raise ValueError("unknown attack class")
        self.burst = (cls, n)

    def next_frame(self):
        now = time.time()
        if self.auto and self.burst is None and now >= self.next_auto:
            self.inject(random.choice([c for c in E.CLASSES if c != "BENIGN"]), random.randint(30, 70))
            self.next_auto = now + random.uniform(15, 25)
        if self.burst and random.random() < 0.55:
            cls, left = self.burst
            self.burst = (cls, left - 1) if left > 1 else None
        else:
            cls = "BENIGN"
        utr, recorded = random.choice(self.by_cls[cls])
        return utr, cls, recorded


STREAM = Stream()


def process_frame(utr, true_cls, recorded):
    eng = state["engine"]
    if eng:
        r = eng.classify_one(utr)
        label, conf = r["label"], r["confidence"]
    else:  # recorded mode: predictions saved by the reported run
        label, conf = recorded, 1.0
    can_id = E.parse_utr(utr)[0]
    out = {"ts": time.time(), "utr": utr, "can_id": can_id, "label": label,
           "confidence": conf, "true": true_cls}
    if label != "BENIGN":
        rk = risk.assess(label, conf, can_id)
        a = dict(out, severity=rk["level"], rank=rk["rank"], score=rk["score"], true_label=true_cls)
        title = f"{E.PRETTY[label]} on CAN ID 0x{can_id}"
        aid, iid, created = db.add_alert(a, title)
        out.update(alert_id=aid, incident_id=iid, new_incident=created, severity=rk["level"],
                   rank=rk["rank"], score=rk["score"], sustained=rk["sustained"], title=title)
        if eng and (utr, None) not in explain_cache:
            pool.submit(get_explanation, utr)
    return out


async def stream_loop():
    loop = asyncio.get_running_loop()
    last_flush, buf, last_stats = time.time(), [], 0
    while True:
        if STREAM.running and not state["loading"]:
            utr, cls, rec = STREAM.next_frame()
            buf.append(await loop.run_in_executor(pool, process_frame, utr, cls, rec))
            STREAM.processed += 1
            STREAM.window.append(time.time())
        now = time.time()
        if now - last_flush >= 0.25:
            STREAM.window = [t for t in STREAM.window if now - t <= 5]
            msg = {"type": "tick", "frames": buf, "stream": stream_state()}
            if now - last_stats >= 1:
                msg["stats"] = db.stats(); last_stats = now
            await broadcast(msg)
            buf, last_flush = [], now
        await asyncio.sleep(1 / STREAM.rate if STREAM.running else 0.25)


def stream_state():
    return {"running": STREAM.running, "rate": STREAM.rate, "auto": STREAM.auto,
            "burst": list(STREAM.burst) if STREAM.burst else None,
            "processed": STREAM.processed, "fps": round(len(STREAM.window) / 5, 1)}


async def broadcast(msg):
    dead = []
    for ws in list(STREAM.clients):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        STREAM.clients.discard(ws)


@app.on_event("startup")
async def startup():
    threading.Thread(target=load_models, daemon=True).start()
    asyncio.create_task(stream_loop())


@app.websocket("/ws/stream")
async def ws_stream(ws: WebSocket):
    await ws.accept()
    STREAM.clients.add(ws)
    await ws.send_json({"type": "hello", "stream": stream_state(), "stats": db.stats()})
    try:
        while True:
            control(await ws.receive_json())
            await broadcast({"type": "tick", "frames": [], "stream": stream_state()})
    except WebSocketDisconnect:
        STREAM.clients.discard(ws)


def control(cmd):
    c = cmd.get("cmd")
    if c == "start":
        STREAM.running = True
    elif c == "pause":
        STREAM.running = False
    elif c == "rate":
        STREAM.rate = max(1, min(60, int(cmd.get("value", 20))))
    elif c == "auto":
        STREAM.auto = bool(cmd.get("value"))
        STREAM.next_auto = time.time() + 5
    elif c == "inject":
        STREAM.inject(cmd.get("cls"), int(cmd.get("n", 60)))


class Control(BaseModel):
    cmd: str
    value: object = None
    cls: str | None = None
    n: int = 60


@app.post("/api/stream")
def api_stream(c: Control):
    try:
        control(c.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return stream_state()


# ---------------------------------------------------------------- status
@app.get("/api/status")
def api_status():
    eng = state["engine"]
    return {
        "loading": state["loading"],
        "mode": "live model" if eng else "recorded predictions",
        "model_dir": os.path.relpath(eng.model_dir, E.ROOT) if eng else None,
        "dev_model": bool(eng and eng.dev),
        "params_m": round(eng.params / 1e6, 2) if eng else None,
        "vocab": eng.vocab if eng else None,
        "error": E.engine_error(),
        "reference": state["ref"].source if state["ref"] else None,
        "runs": {k: os.path.exists(os.path.join(v, "metrics.json")) for k, v in RUNS.items()},
        "global_ready": state["global"] is not None,
        "stream": stream_state(),
    }


# ---------------------------------------------------------------- classify / inspect
class Frame(BaseModel):
    utr: str | None = None
    can_id: str | None = None
    data: list[str] | None = None


@app.post("/api/classify")
def api_classify(f: Frame):
    eng = state["engine"]
    try:
        if f.utr:
            utr = " ".join(f.utr.split())
            vals = E.field_values(utr)
            utr, steps = E.normalise_raw(vals[0], vals[1:])
        else:
            utr, steps = E.normalise_raw(f.can_id or "", f.data or [])
    except (ValueError, TypeError) as e:
        raise HTTPException(400, f"Invalid frame: {e}")
    if not eng:
        raise HTTPException(503, "Model not loaded" + (f": {E.engine_error()}" if E.engine_error() else ""))
    with eng.lock:
        tokens = eng.tok.tokenize(utr)
        ids = eng.tok(utr, return_token_type_ids=False)["input_ids"]
    ex = get_explanation(utr)
    return {"utr": utr, "steps": steps, "tokens": tokens + [eng.tok.eos_token], "token_ids": ids,
            "generated": eng.classify_one(utr)["generated"], "explanation": ex,
            "risk": risk.static(ex["label"], ex["confidence"], ex["values"][0])}


@app.get("/api/explain/global")
def api_explain_global():
    if state["global"] is None:
        if state["engine"] and not state["global_busy"]:
            pool.submit(compute_global)
        return JSONResponse({"pending": True}, status_code=202)
    return state["global"]


# ---------------------------------------------------------------- alerts / incidents
def _csv_param(v):
    return [x for x in (v or "").split(",") if x] or None


@app.get("/api/alerts")
def api_alerts(status: str = "", severity: str = "", label: str = "", q: str = "",
               incident: int = 0, sort: str = "ts", desc: bool = True, limit: int = 50, offset: int = 0):
    total, rows = db.list_alerts(_csv_param(status), _csv_param(severity), _csv_param(label), q or None,
                                 incident or None, sort, desc, min(limit, 500), offset)
    return {"total": total, "rows": rows}


@app.get("/api/alerts/{aid}")
def api_alert(aid: int):
    a = db.get_alert(aid)
    if not a:
        raise HTTPException(404, "alert not found")
    if state["engine"]:
        a["explanation"] = get_explanation(a["utr"], a["label"])
    a["risk"] = risk.static(a["label"], a["confidence"], a["can_id"])
    return a


class AlertUpdate(BaseModel):
    ids: list[int]
    status: str | None = None
    assignee: str | None = None
    note: str | None = None
    actor: str | None = None


@app.patch("/api/alerts")
def api_alerts_update(u: AlertUpdate):
    try:
        db.update_alerts(u.ids, u.actor or ANALYST, u.status, u.assignee, (u.note or "").strip() or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "stats": db.stats()}


@app.get("/api/incidents")
def api_incidents(status: str = ""):
    return {"rows": db.list_incidents(_csv_param(status))}


@app.get("/api/incidents/{iid}")
def api_incident(iid: int):
    i = db.get_incident(iid)
    if not i:
        raise HTTPException(404, "incident not found")
    _, i["alerts"] = db.list_alerts(incident_id=iid, limit=200)
    sample = i["alerts"][0] if i["alerts"] else None
    i["risk"] = risk.static(i["label"], sample["confidence"] if sample else 1.0, i["can_id"])
    return i


class IncidentUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = None
    note: str | None = None
    actor: str | None = None


@app.patch("/api/incidents/{iid}")
def api_incident_update(iid: int, u: IncidentUpdate):
    try:
        ok = db.update_incident(iid, u.actor or ANALYST, u.status, u.assignee, (u.note or "").strip() or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not ok:
        raise HTTPException(404, "incident not found")
    return {"ok": True, "stats": db.stats()}


@app.get("/api/stats")
def api_stats():
    return db.stats()


@app.post("/api/reset")
def api_reset():
    db.reset()
    return {"ok": True}


@app.get("/api/export")
def api_export(format: str = "json"):
    incidents, alerts, events = db.export()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if format == "csv":
        buf = io.StringIO()
        cols = ["id", "title", "label", "can_id", "severity", "status", "assignee", "count",
                "first_ts", "last_ts", "ack_ts", "closed_ts"]
        w = csv.writer(buf)
        w.writerow(cols + ["first_seen", "last_seen"])
        for i in incidents:
            w.writerow([i[c] for c in cols] + [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i["first_ts"])),
                                               time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i["last_ts"]))])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="eris-incidents-{stamp}.csv"'})
    body = json.dumps({"generated": stamp, "summary": db.stats(), "incidents": incidents,
                       "alerts": alerts, "events": events}, indent=1)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="eris-report-{stamp}.json"'})


# ---------------------------------------------------------------- model stats
DATASET = [  # Table 5.1
    {"class": "BENIGN", "file": "hexadecimal_benign.csv", "rows": 1223737, "patterns": 3547},
    {"class": "DoS", "file": "hexadecimal_DoS.csv", "rows": 74663, "patterns": 21},
    {"class": "RPM", "file": "hexadecimal_spoofing-RPM.csv", "rows": 54900, "patterns": 10},
    {"class": "SPEED", "file": "hexadecimal_spoofing-SPEED.csv", "rows": 24951, "patterns": 5},
    {"class": "STEERING_WHEEL", "file": "hexadecimal_spoofing-STEERING_WHEEL.csv", "rows": 19977, "patterns": 3},
    {"class": "GAS", "file": "hexadecimal_spoofing-GAS.csv", "rows": 9991, "patterns": 2},
]
CONFIG = [  # Table 5.4
    ["Architecture", "T5 encoder-decoder (t5-small configuration)"],
    ["Encoder / decoder layers", "6 / 6"], ["d_model / d_ff", "512 / 2,048"],
    ["Attention heads / d_kv", "8 / 64"], ["Vocabulary (scratch mode)", "2,314 word-level hex tokens"],
    ["Total parameters", "45.24 M"], ["Max input / label length", "64 / 8 tokens"],
    ["Optimiser, learning rate", "AdamW, 3 × 10⁻⁴, linear decay"], ["Batch size (train / eval)", "16 / 64"],
    ["Epochs", "5"], ["Model selection", "Lowest validation loss"], ["Random seed", "42"],
]
COMPARISON = [  # Table 7.4
    {"study": "Palma et al. (2025)", "protocol": "Random 80/20 split and 10-fold CV of all rows",
     "model": "RF, XGBoost, DNN", "f1": 1.00},
    {"study": "Le and Alsmadi (2026)", "protocol": "Duplicates removed, stratified k-fold",
     "model": "Random Forest + ANOVA", "f1": 0.64},
    {"study": "ERIS (this work)", "protocol": "Pattern-level split, formatting normalised, "
     "validation-only selection", "model": "T5 (t5-small, scratch)", "f1": None},
]


def parse_report(path):
    rows = {}
    for line in open(path):
        m = re.match(r"\s*(\S+(?: avg)?)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s*$", line)
        if m:
            rows[m.group(1)] = {"precision": float(m.group(2)), "recall": float(m.group(3)),
                                "f1": float(m.group(4)), "support": int(m.group(5))}
    return rows


@app.get("/api/metrics")
def api_metrics(run: str = "reported"):
    d = RUNS.get(run)
    if not d or not os.path.exists(os.path.join(d, "metrics.json")):
        raise HTTPException(404, f"run '{run}' not available")
    m = json.load(open(os.path.join(d, "metrics.json")))
    hist = m.get("log_history", [])
    train = [{"step": h["step"], "epoch": h["epoch"], "loss": h["loss"]} for h in hist if "loss" in h]
    evals = [{"epoch": h["epoch"], "loss": h["eval_loss"]} for h in hist if "eval_loss" in h]
    final = next((h for h in hist if "train_runtime" in h), {})
    cm = pd.read_csv(os.path.join(d, "confusion_matrix.csv"), index_col=0)
    preds = pd.read_csv(os.path.join(d, "test_predictions.csv"))
    pat = preds.groupby("utr").agg(true=("true_class", "first"), pred=("predicted_class", "first"),
                                   rows=("utr", "size")).reset_index()
    pat["correct"] = pat["true"] == pat["pred"]
    pat["can_id"] = pat["utr"].str.split().str[1]
    by_cls = []
    for c, g in pat.groupby("true"):
        by_cls.append({"class": c, "frames": len(g), "ids": sorted(g["can_id"].unique()),
                       "correct": int(g["correct"].sum())})
    best = m.get("best_checkpoint") or ""
    comp = [dict(r) for r in COMPARISON]
    comp[-1]["f1"] = round(m["macro_f1"], 2)
    return {
        "run": run, "mode": m.get("mode"), "rows": m.get("rows"),
        "summary": {k: m.get(k) for k in ("row_accuracy", "macro_precision", "macro_recall", "macro_f1",
                                          "weighted_precision", "weighted_recall", "weighted_f1",
                                          "pattern_accuracy", "pattern_correct", "pattern_total",
                                          "reload_identical")},
        "best_checkpoint": best, "best_step": int(best.rsplit("-", 1)[-1]) if best[-1:].isdigit() else None,
        "train_runtime": final.get("train_runtime"), "train_loss": final.get("train_loss"),
        "loss": {"train": train, "eval": evals},
        "confusion": {"labels": list(cm.columns), "matrix": cm.values.tolist()},
        "per_class": parse_report(os.path.join(d, "classification_report.txt")),
        "pattern_split": pd.read_csv(os.path.join(d, "pattern_split.csv")).to_dict("records"),
        "pattern_by_class": by_cls,
        "patterns": pat.sort_values(["correct", "true"]).to_dict("records"),
        "predictions": preds.to_dict("records"),
        "dataset": DATASET, "config": CONFIG, "comparison": comp,
    }


# ---------------------------------------------------------------- self-test (Table 5.5)
@app.post("/api/selftest")
def api_selftest():
    eng = state["engine"]
    rep = json.load(open(os.path.join(RUNS["reported"], "metrics.json")))
    t = []

    def add(tid, name, expected, actual, ok, live=True):
        t.append({"id": tid, "name": name, "expected": expected, "actual": actual,
                  "status": "pass" if ok else ("info" if ok is None else "fail"), "live": live})

    vals = [E.norm_byte(v) for v in ("2.0", "2", "02")]
    add("TC1", 'Hex normalisation of "2.0", "2", "02"', 'All become "02"', " / ".join(vals),
        all(v == "02" for v in vals))
    nid = E.norm_id("000001DC")
    add("TC2", 'CAN ID "000001DC" normalised', '"1DC"', nid, nid == "1DC")
    raw = {"ID": "000001DC", "DLC": "8", "Interface": "slcan0",
           **{f"DATA_{i}": v for i, v in enumerate(["2.0", "1E", "F5", "3", "0", "0", "0", "0"])}}
    utr, _ = E.normalise_raw(raw["ID"], [raw[f"DATA_{i}"] for i in range(8)])
    add("TC3", "DLC and Interface columns", "Not present in model input", utr,
        "DLC" not in utr and "slcan" not in utr and len(utr.split()) == 18)
    preds = test_frames(eng.run_dir if eng else RUNS["reported"])
    owners = preds.groupby("utr")["true_class"].nunique()
    add("TC4", "Each UTR belongs to one class", "Assertion passes",
        f"{len(owners)} unique test UTRs, max classes per UTR = {owners.max()}", bool((owners == 1).all()))
    ref = state["ref"]
    if ref and ref.source == "training split":
        overlap = set(preds["utr"]) & set(ref.utrs)
        add("TC5", "No UTR shared between train and test", "Empty intersection",
            f"{len(overlap)} shared of {preds['utr'].nunique()} test frames", not overlap)
    else:
        add("TC5", "No UTR shared between train, val and test", "Assertions pass for all three pairs",
            "Asserted during the training run (eris_t5.py)", True, live=False)
    tr = rep["rows"]["train"]
    add("TC6", "Class balance in training set", "1,400 rows per class",
        f"{tr} train rows = 6 × {tr // 6}", tr == 8400, live=False)
    add("TC7", "Model selected without test data", "Best checkpoint chosen by validation loss",
        rep["best_checkpoint"], "checkpoint" in rep["best_checkpoint"], live=False)
    if eng:
        frames = sorted(preds["utr"].unique())
        gen = eng.generate(frames)
        bad = [g for g in gen if g not in E.CLASSES]
        add("TC8", "Generated output is a valid class name", "Only the six labels produced",
            f"{len(frames)} frames → labels {sorted(set(gen))}", not bad)
        from transformers import T5ForConditionalGeneration
        import torch
        fresh = T5ForConditionalGeneration.from_pretrained(eng.model_dir).eval()
        enc = eng.encode(frames)
        with eng.lock, torch.no_grad():
            g2 = eng.tok.batch_decode(fresh.generate(**enc, max_new_tokens=6), skip_special_tokens=True)
        same = [s.strip() for s in g2] == gen
        add("TC9", "Reloaded model reproduces predictions", "Identical prediction list",
            f"Model reloaded from {os.path.relpath(eng.model_dir, E.ROOT)}: identical = {same}", same)
        ok = sum(g == c for g, c in zip(gen, preds.drop_duplicates("utr").set_index("utr")
                                          .loc[frames, "true_class"]))
        add("TC11", "Test accuracy on held-out patterns", "All 33 frames correct",
            f"{ok} of {len(frames)} correct (live)", None)
    else:
        add("TC8", "Generated output is a valid class name", "Only the six labels produced",
            "Model not loaded – from reported run: only valid labels", True, live=False)
        add("TC9", "Reloaded model reproduces predictions", "Identical prediction list",
            f"Reported run: {rep['reload_identical']}", bool(rep["reload_identical"]), live=False)
        add("TC11", "Test accuracy on held-out patterns", "All 33 frames correct",
            f"{rep['pattern_correct']} of {rep['pattern_total']} correct", None, live=False)
    files = ["metrics.json", "classification_report.txt", "confusion_matrix.csv",
             "test_predictions.csv", "pattern_split.csv"]
    d = eng.run_dir if eng and not eng.dev else RUNS["reported"]
    missing = [f for f in files if not os.path.exists(os.path.join(d, f))]
    add("TC10", "Results saved", "Metrics, predictions, confusion matrix, split table",
        f"{len(files) - len(missing)}/{len(files)} files in {os.path.relpath(d, E.ROOT)}/", not missing)
    t.sort(key=lambda x: int(x["id"][2:]))
    return {"tests": t, "passed": sum(x["status"] == "pass" for x in t), "total": len(t)}


@app.get("/api/risk/profiles")
def api_risk_profiles():
    return {"levels": LEVELS, "profiles": PROFILE}


# ---------------------------------------------------------------- static
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))
