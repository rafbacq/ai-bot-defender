# template_generator

Fine-tune **Qwen3-1.7B** (the base model, pulled from Hugging Face) with **LoRA** on
the project's human-written corpora, then have it write honeypot HTML templates in the
style of `website/templates/scraper1.html` — multi-section Wikipedia-style prose with the
project's `{{ var1 }}..{{ var10 }}` canary placeholders woven into it.

This folder is **self-contained and additive**: it only *reads* the sibling corpora
(`../cleaned_intros/`, `../wikipedia_towns_text/`) and writes only inside
`template_generator/`. It does not modify the website, Ansible, or UI layers.

## Pipeline

```
../cleaned_intros/*.txt        (intros, already masked as <var_name>/<var_num>)
../wikipedia_towns_text/*.txt  (full raw articles, masked here via spaCy NER)
        |
        v   prepare_data.py     -> data/sft.jsonl     (instruction -> [[NAME]]/[[NUM]] prose)
        v   train.py            -> models/qwen3-1.7b-townlora/   (LoRA adapter only)
        v   generate_templates.py -> generated_templates/scraper_gen_*.html
```

- **`prepare_data.py`** normalizes both corpora to two placeholder tokens, `[[NAME]]`
  and `[[NUM]]`. The cleaned intros are already masked; the full Wikipedia articles are
  masked with spaCy named-entity recognition (proper names → `[[NAME]]`, dates/quantities
  → `[[NUM]]`). spaCy is optional — without it the dataset is built from `cleaned_intros`
  alone.
- **`train.py`** LoRA-fine-tunes `Qwen/Qwen3-1.7B`. Only the small LoRA adapter is trained
  and saved; the base model is downloaded into your Hugging Face cache and never modified.
- **`generate_templates.py`** prompts the fine-tuned model once per section (Overview /
  History / Geography / Demographics), maps the placeholders to `{{ varN }}`, and wraps the
  result in an HTML page that mirrors `website/templates/scraper1.html`.

## Setup & run (Windows, NVIDIA GPU)

The repo includes `run_windows.ps1`, which does everything (create venv, install the right
PyTorch build, prepare data, train, generate):

```powershell
cd template_generator
powershell -ExecutionPolicy Bypass -File run_windows.ps1
```

It uses [`uv`](https://astral.sh/uv) if present (no admin needed) and falls back to the
`python` on PATH otherwise. To install `uv`:
`winget install astral-sh.uv` **or** `irm https://astral.sh/uv/install.ps1 | iex`.

### macOS / Linux

`run_all.sh` is the bash equivalent (tuned for Apple Silicon / MPS).

### Manual steps

```powershell
uv venv .venv --python 3.11 --seed
uv pip install --python .venv torch --index-url https://download.pytorch.org/whl/cu128  # GPU
uv pip install --python .venv -r requirements.txt
.venv\Scripts\python -m spacy download en_core_web_sm

.venv\Scripts\python prepare_data.py --wiki-limit 3000
.venv\Scripts\python train.py --dtype bfloat16 --seq-len 512 --grad-accum 16 --max-steps 800 --save-every 200
.venv\Scripts\python generate_templates.py --num 12
```

Pick the CUDA index that matches your driver (`cu121` / `cu124` / `cu126` / `cu128`). On a
machine with no NVIDIA GPU, install plain `torch` (CPU) — training is slow but works; pass
`--dtype float32`.

## Running the trained model on another computer

The trained artifact is the **LoRA adapter** in `models/qwen3-1.7b-townlora/` — it is only
a few tens of MB (the multi-GB base model is *not* stored here; it is fetched from Hugging
Face on demand). `models/` is git-ignored, so move the adapter yourself:

1. **Copy** the whole `template_generator/models/qwen3-1.7b-townlora/` folder to the other
   machine (USB, zip, scp, ...). Keep it at the same relative path under `template_generator/`.
2. On that machine, set up the environment (`run_windows.ps1 -GenerateOnly -SkipInstall`
   after a one-time install, or the manual steps above — note **spaCy is not needed just to
   generate**, only `torch` + `transformers` + `peft`).
3. Generate more templates:

   ```powershell
   .venv\Scripts\python generate_templates.py --num 20
   # or, point at a copied adapter elsewhere:
   .venv\Scripts\python generate_templates.py --adapter D:\path\to\qwen3-1.7b-townlora --num 20
   ```

   The first run downloads `Qwen/Qwen3-1.7B` from Hugging Face (needs internet once; it is
   then cached). No login is required — the model is public.

Alternatively, retrain from scratch on the other machine (it has the same corpora) by
running the full pipeline there.

## Deploying a generated template

Each template comes as a pair:

- `scraper_gen_<i>.html` — the page (with `{{ var1 }}..{{ var10 }}` slots).
- `scraper_gen_<i>.txt`  — its **varList**: one faker expression per slot (line N → varN),
  exactly the format of `website/varLists/scraper1.txt`. Name slots use proper-noun
  generators; numeric slots use `fake.random_int(...)` so the numbers render as numbers.

`generate_templates.py` writes to `generated_templates/` and never touches `website/`. To
put one into rotation, copy the HTML in as a new scraper flavor:

```powershell
Copy-Item generated_templates\scraper_gen_3.html ..\website\templates\scraper3.html
# then bump scraper_version to 3 for a site and re-run the playbook
```

For the **canary expressions**, the project's source of truth is `canary_tokens` in
`ansible/group_vars/all.yml` (the Ansible `configure` role renders it into
`website/varLists/scraper<N>.txt` — don't hand-edit those). So paste the 10 lines of
`scraper_gen_3.txt` into the `canary_tokens:` list in `all.yml`, then re-run the playbook.
(If you're running the Flask app standalone without Ansible, you can instead drop the file
straight in as `website/varLists/scraper3.txt`.)

## Useful flags

| Script | Flag | Meaning |
|---|---|---|
| `prepare_data.py` | `--wiki-limit N` | Wikipedia articles to mask (0 = all ~31k; slow). |
| `prepare_data.py` | `--no-wiki` | Use only `cleaned_intros`. |
| `train.py` | `--max-steps N` | Cap optimizer steps (0 = one full epoch). |
| `train.py` | `--dtype bfloat16` | Best on modern NVIDIA GPUs (fastest, low memory). |
| `train.py` | `--save-every N` | Checkpoint the adapter every N steps. |
| `generate_templates.py` | `--num N` | How many templates to write. |
| `generate_templates.py` | `--num-vars 7,8,9,10` | Which var slots carry NUMBERS (numbers rotate across them); the rest carry names. |
| `generate_templates.py` | `--base-only` | Sample the un-fine-tuned model (before/after check). |
| `generate_templates.py` | `--adapter PATH` | Use an adapter from a custom location. |

### Var slots (names vs numbers)

By default vars **1–6 carry names** (var1 is the town name → title/h1/footer) and vars
**7–10 carry numbers** (population, year, area, percentages, …), which rotate across those
four slots so no single var repeats for every number. Change the split with `--num-vars`,
e.g. `--num-vars 4,8,9,10` (the remaining slots become name slots). Note: to make those
slots actually *render* as numbers in the live honeypot, point the matching
`canary_tokens` entries in `ansible/group_vars/all.yml` at numeric faker expressions
(e.g. `fake.date_of_birth().year`, `str(fake.random_int(1000, 90000))`).

There is no test suite; inspect `generated_templates/raw_*.txt` (raw model output) and
`scraper_gen_*.html` (assembled pages) to judge quality.
