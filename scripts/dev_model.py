"""
Development-only stand-in model so the dashboard can be built before the
CICIoV2024 CSVs are available. Same scratch tokenizer as eris_t5.py, a much
smaller T5, trained for a few seconds on the frames in results/test_predictions.csv.

Never used for reported numbers: the dashboard labels it "development model".

Usage: python scripts/dev_model.py [--out results_dev/model]
The dashboard only loads it when ERIS_DEV=1 is set.
"""
import argparse, os, random
import numpy as np, pandas as pd, torch
from tokenizers import Tokenizer, models, pre_tokenizers, processors
from transformers import T5Config, T5ForConditionalGeneration, PreTrainedTokenizerFast

p = argparse.ArgumentParser()
p.add_argument("--out", default="results_dev/model")
p.add_argument("--steps", type=int, default=300)
args = p.parse_args()
random.seed(42); np.random.seed(42); torch.manual_seed(42)

CLASSES = ["BENIGN", "DoS", "GAS", "RPM", "SPEED", "STEERING_WHEEL"]
vocab_list = ["<pad>", "</s>", "<unk>", "CAN_ID"] + [f"D{i}" for i in range(8)] + \
             ["%02X" % b for b in range(256)] + ["%03X" % i for i in range(0x800)] + CLASSES
vocab = {t: i for i, t in enumerate(dict.fromkeys(vocab_list))}
tk = Tokenizer(models.WordLevel(vocab=vocab, unk_token="<unk>"))
tk.pre_tokenizer = pre_tokenizers.WhitespaceSplit()
tk.post_processor = processors.TemplateProcessing(single="$A </s>", special_tokens=[("</s>", 1)])
tokenizer = PreTrainedTokenizerFast(tokenizer_object=tk, pad_token="<pad>",
                                    eos_token="</s>", unk_token="<unk>",
                                    model_input_names=["input_ids", "attention_mask"])
cfg = T5Config(vocab_size=len(vocab), d_model=128, d_kv=32, d_ff=256, num_layers=2,
               num_decoder_layers=2, num_heads=4, pad_token_id=0, eos_token_id=1,
               decoder_start_token_id=0)
model = T5ForConditionalGeneration(cfg)

df = pd.read_csv("results/test_predictions.csv").drop_duplicates("utr")
texts, labels = df["utr"].tolist(), df["true_class"].tolist()
opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
model.train()
for step in range(args.steps):
    idx = np.random.choice(len(texts), 16)
    enc = tokenizer([texts[i] for i in idx], return_tensors="pt", padding=True)
    lab = tokenizer(text_target=[labels[i] for i in idx], return_tensors="pt", padding=True)["input_ids"]
    lab[lab == 0] = -100
    loss = model(**enc, labels=lab).loss
    loss.backward(); opt.step(); opt.zero_grad()
    if step % 100 == 0:
        print(step, float(loss))
os.makedirs(args.out, exist_ok=True)
model.save_pretrained(args.out); tokenizer.save_pretrained(args.out)
print("saved", args.out)
