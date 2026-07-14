#!/usr/bin/env python3
"""
LoRA fine-tune Qwen3-1.7B on the placeholder-prose dataset from prepare_data.py.

Tuned for Apple Silicon (MPS) with limited RAM:
  * hand-rolled training loop (no Trainer/accelerate),
  * gradient checkpointing + batch size 1 + gradient accumulation,
  * attention-only LoRA adapters (the 1.7B base stays frozen),
  * fp32 by default for numerically stable optimization on MPS
    (pass --dtype float16 to halve weight memory if you hit OOM).

Only the LoRA adapters are trained and saved -- the base model is downloaded
from Hugging Face into your HF cache and never modified.

NEW, standalone tool. Writes only into template_generator/models/.

Example (small, tractable demo run on an M1):
    python train.py --limit 3000 --max-steps 80 --grad-accum 8

Example (longer / "thorough" -- run it overnight):
    python train.py --epochs 1 --grad-accum 16        # uses the whole sft.jsonl
"""
#!/usr/bin/env python3
"""
LoRA fine-tune Qwen3-1.7B on the placeholder-prose dataset from prepare_data.py.

Tuned for Apple Silicon (MPS) with limited RAM:
  * hand-rolled training loop (no Trainer/accelerate),
  * gradient checkpointing + batch size 1 + gradient accumulation,
  * attention-only LoRA adapters (the 1.7B base stays frozen),
  * fp32 by default for numerically stable optimization on MPS
    (pass --dtype float16 to halve weight memory if you hit OOM).

Only the LoRA adapters are trained and saved -- the base model is downloaded
from Hugging Face into your HF cache and never modified.

NEW, standalone tool. Writes only into template_generator/models/.

Example (small, tractable demo run on an M1):
    python train.py --limit 3000 --max-steps 80 --grad-accum 8

Example (longer / "thorough" -- run it overnight):
    python train.py --epochs 1 --grad-accum 16        # uses the whole sft.jsonl
"""
import argparse
import json
import os
import random
import time
from pathlib import Path

import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import LoraConfig, get_peft_model

HERE = Path(__file__).resolve().parent
DEFAULT_DATA = HERE / "data" / "sft.jsonl"
DEFAULT_MODEL = os.environ.get("MODEL", "Qwen/Qwen3-1.7B")
# Output dir is derived from the model name at parse time (see main()).
# Override with --out or the MODEL env var.


def apply_chat(tok, messages, add_generation_prompt):
    """Return a list of token ids for a chat, disabling Qwen3 'thinking'.

    Renders to text then re-encodes rather than using tokenize=True: in
    transformers 5.x tokenize=True yields a tokenizers.Encoding object, not the
    plain int list this training loop's collate() needs. add_special_tokens=False
    keeps the chat template's own control tokens from being doubled.
    """
    try:
        text = tok.apply_chat_template(
            messages, tokenize=False,
            add_generation_prompt=add_generation_prompt, enable_thinking=False,
        )
    except TypeError:  # older template without enable_thinking
        text = tok.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=add_generation_prompt,
        )
    return tok(text, add_special_tokens=False)["input_ids"]


def build_example(tok, instruction, target, max_len):
    """Tokenize one (instruction -> target) pair; mask the prompt in the labels."""
    user = [{"role": "user", "content": instruction}]
    prompt_ids = apply_chat(tok, user, add_generation_prompt=True)
    full_ids = apply_chat(tok, user + [{"role": "assistant", "content": target}],
                          add_generation_prompt=False)
    labels = list(full_ids)
    for i in range(min(len(prompt_ids), len(labels))):
        labels[i] = -100  # don't train on the instruction tokens
    return full_ids[:max_len], labels[:max_len]


class JsonlSFT(Dataset):
    def __init__(self, path, tok, max_len, limit=0):
        self.rows = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.rows.append(json.loads(line))
        if limit:
            self.rows = self.rows[:limit]
        self.tok, self.max_len = tok, max_len

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, i):
        r = self.rows[i]
        ids, labels = build_example(self.tok, r["instruction"], r["target"], self.max_len)
        return {"input_ids": ids, "labels": labels}


def collate(batch, pad_id):
    maxlen = max(len(b["input_ids"]) for b in batch)
    input_ids, labels, attn = [], [], []
    for b in batch:
        n = len(b["input_ids"])
        pad = maxlen - n
        input_ids.append(b["input_ids"] + [pad_id] * pad)
        labels.append(b["labels"] + [-100] * pad)
        attn.append([1] * n + [0] * pad)
    return torch.tensor(input_ids), torch.tensor(labels), torch.tensor(attn)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help="HuggingFace model ID or local path (default: $MODEL env var or Qwen/Qwen3-1.7B)")
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--out", type=Path, default=None,
                    help="adapter output dir (default: models/<model-slug>-lora)")
    ap.add_argument("--limit", type=int, default=0, help="cap #examples used (0 = all in file)")
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--max-steps", type=int, default=0, help="optimizer-step cap (0 = off)")
    ap.add_argument("--seq-len", type=int, default=384)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--lora-r", type=int, default=8)
    ap.add_argument("--lora-alpha", type=int, default=16)
    ap.add_argument("--lora-target", choices=["attn", "all"], default="attn",
                    help="attn = q/k/v/o only (lean, MPS-friendly); "
                         "all = attention + MLP (gate/up/down) for a fuller fine-tune")
    ap.add_argument("--dtype", choices=["float32", "float16", "bfloat16"], default="float32",
                    help="float32 = safest (MPS/CPU); bfloat16 = best on modern CUDA GPUs; "
                         "float16 = least memory (LoRA params kept in fp32 for stability)")
    ap.add_argument("--no-grad-ckpt", action="store_true",
                    help="disable gradient checkpointing (faster, more memory; fine on a big GPU)")
    ap.add_argument("--save-every", type=int, default=0, help="checkpoint every N steps (0 = only at end)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    # Derive output dir from model name if not explicitly set.
    if args.out is None:
        model_slug = args.model.replace("/", "-").replace(".", "_")
        args.out = HERE / "models" / f"{model_slug}- lora"

    torch.manual_seed(args.seed)
    random.seed(args.seed)
    if torch.backends.mps.is_available():
        device = "mps"
    elif torch.cuda.is_available():
        device = "cuda"
    else:
        device = "cpu"
    dtype = {"float32": torch.float32, "float16": torch.float16,
             "bfloat16": torch.bfloat16}[args.dtype]
    print(f"device={device} dtype={args.dtype} model={args.model}", flush=True)

    tok = AutoTokenizer.from_pretrained(args.model)
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token

    model = AutoModelForCausalLM.from_pretrained(args.model, torch_dtype=dtype)
    # Auto-detect projection layer names so this works across Qwen3 sizes/variants.
    all_module_names = {n.split(".")[-1] for n, _ in model.named_modules()}
    attn_keys  = {"q_proj", "k_proj", "v_proj", "o_proj"}
    mlp_keys   = {"gate_proj", "up_proj", "down_proj"}
    target_modules = sorted(attn_keys & all_module_names)
    if args.lora_target == "all":
        target_modules += sorted(mlp_keys & all_module_names)
    lora = LoraConfig(
        r=args.lora_r, lora_alpha=args.lora_alpha, lora_dropout=0.05, bias="none",
        task_type="CAUSAL_LM", target_modules=target_modules,
    )
    model = get_peft_model(model, lora)
    if not args.no_grad_ckpt:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()
    model.config.use_cache = False
    # fp16 lacks the dynamic range to optimize tiny LoRA grads safely without a loss
    # scaler (which is CUDA-only), so keep the trainable params in fp32 in that case.
    # bf16/fp32 are stable as-is.
    if dtype == torch.float16:
        for p in model.parameters():
            if p.requires_grad:
                p.data = p.data.float()
    model.to(device)
    model.print_trainable_parameters()

    ds = JsonlSFT(args.data, tok, args.seq_len, args.limit)
    if len(ds) == 0:
        raise SystemExit(f"No examples in {args.data}. Run prepare_data.py first.")
    dl = DataLoader(ds, batch_size=args.batch_size, shuffle=True,
                    collate_fn=lambda b: collate(b, tok.pad_token_id))
    print(f"training examples: {len(ds)}", flush=True)

    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=args.lr)

    def save(tag=""):
        out = args.out if not tag else args.out.with_name(args.out.name + f"-{tag}")
        out.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(out)
        tok.save_pretrained(out)
        print(f"  saved adapter -> {out}", flush=True)

    model.train()
    step = micro = 0
    running = 0.0
    t0 = time.time()
    opt.zero_grad()
    stop = False
    for epoch in range(args.epochs):
        for input_ids, labels, attn in dl:
            input_ids, labels, attn = input_ids.to(device), labels.to(device), attn.to(device)
            out = model(input_ids=input_ids, attention_mask=attn, labels=labels)
            (out.loss / args.grad_accum).backward()
            running += out.loss.item()
            micro += 1
            if micro % args.grad_accum == 0:
                torch.nn.utils.clip_grad_norm_(
                    [p for p in model.parameters() if p.requires_grad], 1.0)
                opt.step()
                opt.zero_grad()
                step += 1
                avg = running / args.grad_accum
                running = 0.0
                print(f"epoch {epoch} | step {step} | loss {avg:.4f} | "
                      f"{micro} micro-batches | {time.time() - t0:.0f}s", flush=True)
                if args.save_every and step % args.save_every == 0:
                    save(tag=f"step{step}")
                if args.max_steps and step >= args.max_steps:
                    stop = True
                    break
        if stop:
            break

    save()
    print(f"Done. {step} optimizer steps in {time.time() - t0:.0f}s.", flush=True)


if __name__ == "__main__":
    main()