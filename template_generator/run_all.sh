#!/usr/bin/env bash
# End-to-end (macOS/Linux): venv -> install -> prepare data -> LoRA fine-tune -> generate.
# (On Windows use run_windows.ps1.)
#
# Defaults are sized for a *tractable demo* on an Apple M1 / 16 GB. Override via env:
#   PY=python3.12 WIKI_LIMIT=1500 MAX_STEPS=400 GRAD_ACCUM=16 NUM=12 ./run_all.sh
#
# For a "thorough" run (e.g. on a CUDA GPU), use the whole corpus and a full epoch:
#   WIKI_LIMIT=3000 MAX_STEPS=0 LORA_TARGET=all DTYPE=bfloat16 NUM=12 ./run_all.sh
#!/usr/bin/env bash
# End-to-end (macOS/Linux): venv -> install -> prepare data -> LoRA fine-tune -> generate.
# (On Windows use run_windows.ps1.)
#
# Defaults are sized for a *tractable demo* on an Apple M1 / 16 GB. Override via env:
#   PY=python3.12 MODEL=Qwen/Qwen3-4B WIKI_LIMIT=1500 MAX_STEPS=400 GRAD_ACCUM=16 NUM=12 ./run_all.sh
#
# To use a locally downloaded model (avoids re-downloading from HuggingFace):
#   MODEL=/path/to/local/qwen3 ./run_all.sh
#
# For a "thorough" run (e.g. on a CUDA GPU), use the whole corpus and a full epoch:
#   MODEL=Qwen/Qwen3-4B WIKI_LIMIT=3000 MAX_STEPS=0 LORA_TARGET=all DTYPE=bfloat16 NUM=12 ./run_all.sh
set -euo pipefail
cd "$(dirname "$0")"

PY="${PY:-python3}"
# PyTorch publishes wheels for CPython 3.9-3.13; bail early on anything else
# (this machine's default python3 is 3.14, which has no torch wheel yet).
if ! "$PY" -c 'import sys; raise SystemExit(0 if (3,9) <= sys.version_info[:2] <= (3,13) else 1)'; then
  echo "ERROR: '$PY' is $($PY -V 2>&1). Use Python 3.9-3.13, e.g.:  PY=python3.12 $0" >&2
  exit 1
fi

WIKI_LIMIT="${WIKI_LIMIT:-1500}"   # Wikipedia ARTICLES to mask (0 = all ~31k; slow)
MAX_STEPS="${MAX_STEPS:-400}"      # optimizer-step cap (0 = one full epoch)
GRAD_ACCUM="${GRAD_ACCUM:-16}"
SEQ_LEN="${SEQ_LEN:-512}"
LORA_TARGET="${LORA_TARGET:-attn}" # attn (lean) or all (attention + MLP)
DTYPE="${DTYPE:-float32}"          # float32 safe on MPS/CPU; bfloat16 best on CUDA
NUM="${NUM:-12}"
MODEL="${MODEL:-Qwen/Qwen3-1.7B}"  # HuggingFace model ID or local path

if [ ! -d .venv ]; then
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm || echo "(spaCy model download failed; wiki masking will be skipped)"

python prepare_data.py --wiki-limit "$WIKI_LIMIT"
python train.py --model "$MODEL" --max-steps "$MAX_STEPS" --grad-accum "$GRAD_ACCUM" \
  --seq-len "$SEQ_LEN" --lora-target "$LORA_TARGET" --dtype "$DTYPE" --save-every 500
python generate_templates.py --num "$NUM"

echo "Done. See template_generator/generated_templates/"