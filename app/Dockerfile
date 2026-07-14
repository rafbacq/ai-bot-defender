# Unified web app for AI Bot Defender.
#
# Bakes in the Docker CLI + compose plugin AND ansible-core so the app can deploy
# sites (ansible-playbook) and read the proxy / per-site databases (docker compose
# exec) against the host daemon. Like the old UI container, the project is
# bind-mounted at the SAME absolute path at runtime (path mirroring) so docker
# build contexts resolve identically inside and outside the container.
#
# Build context is the repository ROOT (it needs both app/ and querying/):
#   docker compose -f docker-compose.app.yml up -d --build
FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg \
        -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    . /etc/os-release && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        docker-ce-cli docker-compose-plugin && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir ansible-core==2.17.4 && \
    ansible-galaxy collection install community.general

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Template Generator ML stack -------------------------------------------
# The /generator page authors honeypot pages with a fine-tuned Qwen3-1.7B + LoRA
# model, run as an in-container subprocess (python3 generate_templates.py). That
# needs torch/transformers/peft, so they are baked in here.
#
# torch is installed from PyTorch's CUDA 12.8 index (cu128) because the target GPU
# is Blackwell (RTX 50-series, sm_120); the default PyPI/CPU and older-CUDA wheels
# don't support it. The GPU is passed through in docker-compose.app.yml; without a
# usable GPU torch still runs on CPU (slower). The Qwen3-1.7B base model downloads
# at first generation into HF_HOME (a persistent volume in the compose file).
#
# PIN the version: an unpinned `pip install torch` is non-reproducible — as new
# cu128 releases land, pip's resolver can backtrack across incompatible versions
# and fail with ResolutionImpossible (this bit a rebuild once). Pinning fixes the
# resolved set and keeps the build deterministic. Bump this deliberately (and the
# rest of the ML stack together) when you want a newer torch.
RUN pip install --no-cache-dir torch==2.11.0 --index-url https://download.pytorch.org/whl/cu128
COPY app/requirements-ml.txt .
RUN pip install --no-cache-dir -r requirements-ml.txt

# Crawler-graph (Direction 6a) analysis deps for the /intel page. Installed in a
# late, cheap layer AFTER the heavy ML stack so changing them never invalidates
# the torch cache.
COPY crawler_graph/requirements.txt ./crawler_graph-requirements.txt
RUN pip install --no-cache-dir -r crawler_graph-requirements.txt

# GraphSAGE GNN (torch_geometric) for in-app provider attribution on /intel.
# torch is ALREADY present (installed above for the template generator), so this
# is a small, pure-Python add — the /intel "Recompute with GraphSAGE GNN" button
# trains the model in-process, no terminal step. (The optional pyg-lib/torch-scatter
# compiled extensions are NOT needed: SAGEConv runs on torch's native ops; PyG just
# prints a benign "not found" note. scikit-learn is omitted — only the unused
# KMeans-over-embeddings path needs it.) CPU is fine for this graph size.
RUN pip install --no-cache-dir "torch_geometric>=2.5"

# auto_query detection engine deps (LiteLLM target querying, internal GPT-4.1
# client, RapidFuzz attribution matcher, openpyxl manual uploads). A late,
# cheap layer for the same reason as crawler_graph above.
COPY app/requirements-autoquery.txt .
RUN pip install --no-cache-dir -r requirements-autoquery.txt

# Local signup/login dependencies live in their own late layer. Keeping this
# small add-on after the multi-gigabyte Torch/ML layers means an auth dependency
# change never forces Docker to rebuild the GPU stack.
COPY app/requirements-auth.txt .
RUN pip install --no-cache-dir -r requirements-auth.txt

# Baked-in copy (overridden by the runtime bind mount in compose).
COPY app ./app
COPY querying ./querying
COPY auto_query ./auto_query
COPY crawler_graph ./crawler_graph

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
