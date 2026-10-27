"""
ERIS inference engine: frame normalisation, T5 classification, class probabilities.

Normalisation is copied from eris_t5.py (that module runs its pipeline at import
time, so it cannot be imported). Keep the two in sync.
"""
import os, threading

import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLASSES = ["BENIGN", "DoS", "GAS", "RPM", "SPEED", "STEERING_WHEEL"]
FIELDS = ["CAN_ID"] + [f"D{i}" for i in range(8)]
PRETTY = {"BENIGN": "Benign", "DoS": "DoS flooding", "GAS": "GAS pedal spoofing",
          "RPM": "RPM spoofing", "SPEED": "SPEED spoofing",
          "STEERING_WHEEL": "Steering-wheel spoofing"}


# ---------------------------------------------------------------- normalisation (= eris_t5.py)
def norm_byte(v):  # "2.0" / "2" / "02" -> "02"
    return "%02X" % int(str(v).strip().replace(".0", ""), 16)


def norm_id(v):  # "000001DC" -> "1DC"
    return "%03X" % int(str(v).strip(), 16)


def to_utr(can_id, data):
    return "CAN_ID " + can_id + "".join(f" D{i} {b}" for i, b in enumerate(data))


def parse_utr(utr):
    t = utr.split()
    if len(t) != 18 or t[0] != "CAN_ID" or [t[i] for i in range(2, 18, 2)] != FIELDS[1:]:
        raise ValueError("not a UTR: expected 'CAN_ID <id> D0 <b0> ... D7 <b7>'")
    return t[1], [t[i] for i in range(3, 18, 2)]


def normalise_raw(raw_id, raw_bytes):
    """Raw CSV-style values -> (utr, per-field steps). Raises ValueError on bad input."""
    if len(raw_bytes) != 8:
        raise ValueError("a CAN frame needs exactly 8 data bytes")
    steps, data = [], []
    can_id = norm_id(raw_id)
    if int(can_id, 16) >= 0x800:
        raise ValueError("CAN ID must be an 11-bit identifier (000-7FF)")
    steps.append({"field": "CAN_ID", "raw": str(raw_id), "normalised": can_id})
    for i, v in enumerate(raw_bytes):
        b = norm_byte(v)
        if int(b, 16) > 0xFF:
            raise ValueError(f"D{i} is not a byte")
        data.append(b)
        steps.append({"field": f"D{i}", "raw": str(v), "normalised": b})
    return to_utr(can_id, data), steps


def field_values(utr):
    can_id, data = parse_utr(utr)
    return [can_id] + data


def utr_from_values(vals):
    return to_utr(vals[0], vals[1:])


# ---------------------------------------------------------------- model discovery
def find_model_dir():
    env = os.environ.get("ERIS_MODEL")
    cands = [env] if env else []
    runs = ("results_live", "results") + (("results_dev",) if os.environ.get("ERIS_DEV") else ())
    cands += [os.path.join(ROOT, d, "model") for d in runs]
    for c in cands:
        if c and os.path.exists(os.path.join(c, "config.json")):
            return c
    return None


def run_dir_for(model_dir):
    return os.path.dirname(model_dir) if model_dir else None


# ---------------------------------------------------------------- engine
class Engine:
    def __init__(self, model_dir):
        from transformers import AutoTokenizer, T5ForConditionalGeneration
        torch.manual_seed(42)
        self.model_dir = model_dir
        self.run_dir = run_dir_for(model_dir)
        self.dev = os.path.basename(self.run_dir) == "results_dev"
        self.tok = AutoTokenizer.from_pretrained(model_dir)
        self.model = T5ForConditionalGeneration.from_pretrained(
            model_dir, attn_implementation="eager").eval()
        self.lock = threading.RLock()
        self.params = sum(p.numel() for p in self.model.parameters())
        self.vocab = len(self.tok)
        self.unk = self.tok.unk_token or "<unk>"
        # label token sequences (incl. EOS), padded with -100
        ids = [self.tok(text_target=c)["input_ids"] for c in CLASSES]
        L = max(map(len, ids))
        lab = torch.full((len(CLASSES), L), -100, dtype=torch.long)
        for i, s in enumerate(ids):
            lab[i, :len(s)] = torch.tensor(s)
        self.label_ids = lab
        self._cache = {}

    # -- encoding
    def encode(self, texts, offsets=False):
        with self.lock:  # fast tokenizers are not thread-safe
            return self.tok(texts, return_tensors="pt", padding=True, truncation=True, max_length=64,
                            return_token_type_ids=False, return_offsets_mapping=offsets)

    def field_token_index(self, utr):
        """For each of the 9 fields, the token positions holding its value."""
        with self.lock:
            enc = self.tok(utr, return_offsets_mapping=True, return_token_type_ids=False)
        spans, pos = [], 0
        for f, v in zip(FIELDS, field_values(utr)):
            start = utr.index(f + " " + v, pos) + len(f) + 1
            spans.append((start, start + len(v)))
            pos = start + len(v)
        out = [[] for _ in FIELDS]
        for ti, (a, b) in enumerate(enc["offset_mapping"]):
            if a == b:
                continue
            for k, (s, e) in enumerate(spans):
                if a < e and b > s:
                    out[k].append(ti)
        return out, enc["input_ids"]

    # -- scoring
    def class_logprobs(self, attention_mask, input_ids=None, inputs_embeds=None):
        """[B, 6] log p(class | frame), normalised over the six class names."""
        m = self.model
        enc = m.encoder(input_ids=input_ids, inputs_embeds=inputs_embeds,
                        attention_mask=attention_mask).last_hidden_state
        B, C = enc.shape[0], len(CLASSES)
        h = enc.repeat_interleave(C, 0)
        am = attention_mask.repeat_interleave(C, 0)
        lab = self.label_ids.repeat(B, 1)
        dec_in = m._shift_right(lab)  # -100 -> pad
        logits = m(encoder_outputs=(h,), attention_mask=am, decoder_input_ids=dec_in).logits
        lp = torch.log_softmax(logits.float(), -1)
        tok_lp = lp.gather(-1, lab.clamp(min=0).unsqueeze(-1)).squeeze(-1) * (lab != -100)
        seq = tok_lp.sum(-1).view(B, C)
        return torch.log_softmax(seq, -1)

    @torch.no_grad()
    def probs(self, texts, bs=64):
        out = []
        with self.lock:
            for i in range(0, len(texts), bs):
                enc = self.encode(texts[i:i + bs])
                out.append(self.class_logprobs(enc["attention_mask"], enc["input_ids"]).exp())
        return torch.cat(out).numpy()

    @torch.no_grad()
    def generate(self, texts, bs=64):
        """Same decoding as predict() in eris_t5.py."""
        out = []
        with self.lock:
            for i in range(0, len(texts), bs):
                enc = self.encode(texts[i:i + bs])
                g = self.model.generate(**enc, max_new_tokens=6)
                out += [s.strip() for s in self.tok.batch_decode(g, skip_special_tokens=True)]
        return out

    def classify(self, texts):
        todo = [t for t in dict.fromkeys(texts) if t not in self._cache]
        if todo:
            gen = self.generate(todo)
            pr = self.probs(todo)
            for t, g, p in zip(todo, gen, pr):
                label = g if g in CLASSES else CLASSES[int(p.argmax())]
                self._cache[t] = {"label": label, "generated": g,
                                  "confidence": float(p[CLASSES.index(label)]),
                                  "probs": {c: float(x) for c, x in zip(CLASSES, p)}}
        return [self._cache[t] for t in texts]

    def classify_one(self, utr):
        return self.classify([utr])[0]


_engine, _engine_err = None, None


def get_engine():
    global _engine, _engine_err
    if _engine is None and _engine_err is None:
        d = find_model_dir()
        if d is None:
            _engine_err = "no trained model found (results_live/model, results/model)"
        else:
            try:
                _engine = Engine(d)
            except Exception as e:  # keep the dashboard up in recorded mode
                _engine_err = f"{type(e).__name__}: {e}"
    return _engine


def engine_error():
    return _engine_err
