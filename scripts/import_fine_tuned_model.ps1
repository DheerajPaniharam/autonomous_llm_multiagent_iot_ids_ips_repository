# ==============================================================================
# PowerShell Script: Import and Register Fine-Tuned LLM in Local Ollama
# ==============================================================================

$GGUF_DIR = "$PSScriptRoot\..\models\llm"
$MODELFILE = "$GGUF_DIR\Modelfile"
$MODEL_NAME = "qwen2.5-3b-iot-ids"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  IoT IDS/IPS: Ollama Fine-Tuned Model Registration Script   " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Check if Ollama is running
try {
    $response = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 3 -ErrorAction Stop
    Write-Host "[OK] Ollama service is running and accessible." -ForegroundColor Green
}
catch {
    Write-Host "[!] Ollama is not running on http://localhost:11434!" -ForegroundColor Red
    Write-Host "    Please start Ollama (or run 'docker compose up -d ollama') and re-run this script." -ForegroundColor Yellow
    exit 1
}

# 2. Check for GGUF file
$ggufFiles = Get-ChildItem -Path $GGUF_DIR -Filter "*.gguf" -ErrorAction SilentlyContinue

if (-not $ggufFiles -or $ggufFiles.Count -eq 0) {
    Write-Host "[X] No .gguf model file found in: $GGUF_DIR" -ForegroundColor Red
    Write-Host "    Please place your downloaded .gguf file into: $GGUF_DIR" -ForegroundColor Yellow
    exit 1
}

$targetGguf = $ggufFiles[0]
Write-Host "[OK] Found GGUF file: $($targetGguf.Name)" -ForegroundColor Green

# Update FROM line in Modelfile to match the actual GGUF file name
$modelfileContent = Get-Content -Path $MODELFILE -Raw
$modelfileContent = $modelfileContent -replace 'FROM\s+\S+', "FROM ./$($targetGguf.Name)"
Set-Content -Path $MODELFILE -Value $modelfileContent

# 3. Create Ollama Model
Write-Host ""
Write-Host "[*] Registering '$MODEL_NAME' in Ollama from $MODELFILE..." -ForegroundColor Cyan

$success = $false

if (Get-Command "ollama" -ErrorAction SilentlyContinue) {
    Set-Location -Path $GGUF_DIR
    & ollama create $MODEL_NAME -f Modelfile
    if ($LASTEXITCODE -eq 0) { $success = $true }
    Set-Location -Path $PSScriptRoot
}
elseif (Test-Path "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe") {
    $ollamaBin = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
    Set-Location -Path $GGUF_DIR
    & $ollamaBin create $MODEL_NAME -f Modelfile
    if ($LASTEXITCODE -eq 0) { $success = $true }
    Set-Location -Path $PSScriptRoot
}
elseif (Get-Command "wsl" -ErrorAction SilentlyContinue) {
    Write-Host "[*] Native Windows Ollama CLI not in PATH. Checking WSL..." -ForegroundColor Yellow
    $wslCheck = wsl which ollama 2>$null
    if ($wslCheck) {
        Write-Host "[OK] Found Ollama in WSL ($($wslCheck.Trim())). Executing via WSL..." -ForegroundColor Green
        $wslGgufDir = (wsl wslpath -u ($GGUF_DIR -replace '\\', '/')).Trim()
        wsl bash -c "cd '$wslGgufDir' && ollama create $MODEL_NAME -f Modelfile"
        if ($LASTEXITCODE -eq 0) { $success = $true }
    }
}
elseif (Get-Command "docker" -ErrorAction SilentlyContinue) {
    $dockerCheck = docker ps --filter "name=ollama" --format "{{.Names}}" 2>$null
    if ($dockerCheck) {
        Write-Host "[OK] Found Ollama Docker container. Executing via Docker..." -ForegroundColor Green
        docker exec -i ollama ollama create $MODEL_NAME -f /root/.ollama/models/Modelfile
        if ($LASTEXITCODE -eq 0) { $success = $true }
    }
}

if ($success) {
    Write-Host "[OK] Model '$MODEL_NAME' successfully registered in Ollama!" -ForegroundColor Green
}
else {
    Write-Host "[X] Failed to create model in Ollama." -ForegroundColor Red
    Write-Host "    Make sure Ollama CLI is accessible on Windows, WSL, or Docker." -ForegroundColor Yellow
    exit 1
}

# 4. Quick Inference Test
Write-Host ""
Write-Host "[*] Running rapid test inference..." -ForegroundColor Cyan
$testPrompt = "Attack Type: TCP SYN Flood`nComposite Threat Score: 0.95`nSource IP: 192.168.1.100`nDestination IP: 192.168.1.1`nProtocol: TCP`nFlow Duration: 0.05s`nRecent Events (last 5): SYN Flood@0.94`nBaseline Deviation: Critical"

$testPayload = @{
    model = $MODEL_NAME
    prompt = $testPrompt
    stream = $false
} | ConvertTo-Json

try {
    $testResult = Invoke-RestMethod -Uri "http://localhost:11434/api/generate" -Method Post -Body $testPayload -ContentType "application/json" -TimeoutSec 10
    Write-Host "[OK] Model Response:" -ForegroundColor Green
    Write-Host $testResult.response -ForegroundColor White
}
catch {
    Write-Host "[!] Test inference failed: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Next Step: Ensure your .env file contains:" -ForegroundColor Yellow
Write-Host "OLLAMA_MODEL=$MODEL_NAME" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
