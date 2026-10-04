#!/bin/bash
# Training script for IoT IDS ML models

echo "=== IoT IDS ML Model Training ==="
echo "This script trains the LightGBM supervised model and the Isolation Forest anomaly model"
echo ""

# Check if data exists
if [ ! -f "data/mock_iot_traffic.csv" ]; then
    echo "Error: Training data not found at data/mock_iot_traffic.csv"
    echo "Please ensure your training data is available."
    exit 1
fi

# Train the supervised model first (creates preprocessors)
echo "Step 1: Training LightGBM supervised classifier..."
python models/train_realtime_optimized.py

if [ $? -ne 0 ]; then
    echo "Error: supervised model training failed"
    exit 1
fi

# Train Isolation Forest (uses preprocessors from supervised training)
echo ""
echo "Step 2: Training Isolation Forest..."
python models/train_isolation_forest.py

if [ $? -ne 0 ]; then
    echo "Error: Isolation Forest training failed"
    exit 1
fi

echo ""
echo "=== Training Complete ==="
echo "Models saved in models/ directory:"
echo "  - lgb_model_optimized.joblib (LightGBM supervised classifier)"
echo "  - if_model_optimized.joblib (Isolation Forest anomaly detector)"
echo "  - scaler_optimized.joblib (Feature scaler)"
echo "  - label_encoder.joblib (Label encoder)"
echo "  - metadata_optimized.json (Training metadata)"
echo ""
echo "The models are now ready for use by the detection agents."
