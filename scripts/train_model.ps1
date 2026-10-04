# IoT IDS ML Model Training Script (PowerShell)
# This script trains both Random Forest and Isolation Forest models

Write-Host "=== IoT IDS ML Model Training ===" -ForegroundColor Green
Write-Host "This script trains the LightGBM supervised model and the Isolation Forest anomaly model"
Write-Host ""

# Check if data exists
$dataPath = "data/mock_iot_traffic.csv"
if (-not (Test-Path $dataPath)) {
    Write-Host "Error: Training data not found at $dataPath" -ForegroundColor Red
    Write-Host "Please ensure your training data is available."
    exit 1
}

# Train the supervised model first (creates preprocessors)
Write-Host "Step 1: Training LightGBM supervised classifier..." -ForegroundColor Yellow
& python models/train_realtime_optimized.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: supervised model training failed" -ForegroundColor Red
    exit 1
}

# Train Isolation Forest (uses preprocessors from supervised training)
Write-Host ""
Write-Host "Step 2: Training Isolation Forest..." -ForegroundColor Yellow
& python models/train_isolation_forest.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Isolation Forest training failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Training Complete ===" -ForegroundColor Green
Write-Host "Models saved in models/ directory:"
Write-Host "  - lgb_model_optimized.joblib (LightGBM supervised classifier)"
Write-Host "  - if_model_optimized.joblib (Isolation Forest anomaly detector)"
Write-Host "  - scaler_optimized.joblib (Feature scaler)"
Write-Host "  - label_encoder.joblib (Label encoder)"
Write-Host "  - metadata_optimized.json (Training metadata)"
Write-Host ""
Write-Host "The models are now ready for use by the detection agents." -ForegroundColor Green