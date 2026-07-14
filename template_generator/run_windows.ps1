<#
.SYNOPSIS
  End-to-end (Windows): venv -> install -> prepare data -> LoRA fine-tune -> generate templates.

.DESCRIPTION
  The Windows counterpart of run_all.sh. Creates template_generator\.venv (with uv if
  available, else the `python` on PATH), installs the CUDA or CPU build of PyTorch
  automatically based on whether an NVIDIA GPU is detected, then runs the three pipeline
  stages. Re-run any time; the venv is reused.

.EXAMPLE
  # Full pipeline with defaults (good, thorough run on a CUDA GPU):
  powershell -ExecutionPolicy Bypass -File run_windows.ps1

.EXAMPLE
  # Use a locally downloaded model (skips HuggingFace download):
  powershell -ExecutionPolicy Bypass -File run_windows.ps1 -Model C:\models\qwen3-1.7b

.EXAMPLE
  # Just regenerate templates from an already-trained adapter (e.g. on another PC):
  powershell -ExecutionPolicy Bypass -File run_windows.ps1 -GenerateOnly -Num 15
#>
[CmdletBinding()]
param(
  [string]$Model      = $env:MODEL ?? "Qwen/Qwen3-1.7B",  # HuggingFace ID or local path
  [int]$WikiLimit  = 3000,      # Wikipedia ARTICLES to mask for training data (0 = all ~31k)
  [int]$MaxSteps   = 800,       # optimizer steps (0 = one full epoch over the data)
  [int]$GradAccum  = 16,
  [int]$SeqLen     = 512,
  [int]$Num        = 12,        # templates to generate
  [string]$CudaIndex = "cu128", # PyTorch CUDA wheel index: cu121/cu124/cu126/cu128
  [switch]$PrepareOnly,
  [switch]$TrainOnly,
  [switch]$GenerateOnly,
  [switch]$SkipInstall
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$venv = Join-Path $PSScriptRoot ".venv"
$py   = Join-Path $venv "Scripts\python.exe"

function Find-Uv {
  $c = Get-Command uv -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $local = Join-Path $env:USERPROFILE ".uvbin\uv.exe"
  if (Test-Path $local) { return $local }
  return $null
}

if (-not $SkipInstall) {
  $uv = Find-Uv
  if (-not (Test-Path $py)) {
    Write-Host "==> creating venv at $venv"
    if ($uv) { & $uv venv $venv --python 3.11 --seed }
    else {
      $sys = (Get-Command python -ErrorAction SilentlyContinue).Source
      if (-not $sys) { throw "No 'python' or 'uv' found. Install Python 3.10-3.13 or uv (https://astral.sh/uv)." }
      & $sys -m venv $venv
    }
  }
  $hasGpu = $false
  try { nvidia-smi | Out-Null; if ($LASTEXITCODE -eq 0) { $hasGpu = $true } } catch {}
  $torchArgs = if ($hasGpu) {
    Write-Host "==> NVIDIA GPU detected: installing CUDA ($CudaIndex) PyTorch"
    @("torch", "--index-url", "https://download.pytorch.org/whl/$CudaIndex")
  } else {
    Write-Host "==> no NVIDIA GPU detected: installing CPU PyTorch"
    @("torch")
  }
  if ($uv) {
    & $uv pip install --python $py @torchArgs
    & $uv pip install --python $py -r requirements.txt
  } else {
    & $py -m pip install --upgrade pip
    & $py -m pip install @torchArgs
    & $py -m pip install -r requirements.txt
  }
  & $py -m spacy download en_core_web_sm
}

if (-not (Test-Path $py)) { throw "venv python not found at $py (run without -SkipInstall first)." }

$runPrep = -not ($TrainOnly -or $GenerateOnly)
$runTrain = -not ($PrepareOnly -or $GenerateOnly)
$runGen  = -not ($PrepareOnly -or $TrainOnly)

if ($runPrep) {
  Write-Host "`n==> [1/3] preparing dataset (cleaned_intros + $WikiLimit masked wiki articles)"
  & $py prepare_data.py --wiki-limit $WikiLimit
}
if ($runTrain) {
  Write-Host "`n==> [2/3] LoRA fine-tuning $Model (bf16, $MaxSteps steps)"
  & $py train.py --model $Model --dtype bfloat16 --seq-len $SeqLen --grad-accum $GradAccum --max-steps $MaxSteps --save-every 200
}
if ($runGen) {
  Write-Host "`n==> [3/3] generating $Num templates"
  & $py generate_templates.py --num $Num
}
Write-Host "`nDone. See template_generator\generated_templates\"