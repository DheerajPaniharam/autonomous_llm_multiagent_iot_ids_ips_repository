#!/usr/bin/env bash
# ==============================================================================
# Bash Script: Import and Register Fine-Tuned LLM in Local Ollama (Ubuntu / Linux)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GGUF_DIR="${SCRIPT_DIR}/../models/llm"
MODELFILE="${GGUF_DIR}/Modelfile"
MODEL_NAME="qwen2.5-3b-iot-ids"

echo -e "\033[1;36m============================================================\033[0m"
echo -e "\033[1;36m  IoT IDS/IPS: Ollama Fine-Tuned Model Registration (Linux)  \033[0m"
echo -e "\033[1;36m============================================================\033[0m"

# 1. Check if Ollama is running
if curl -s -f "http://localhost:11434/api/tags" > /dev/null 2>&1; then
    echo -e "\033[1;32m[OK] Ollama service is running and accessible.\033[0m"
else
    echo -e "\033[1;31m[!] Ollama is not running on http://localhost:11434!\033[0m"
    echo -e "\033[1;33m    Please start Ollama ('ollama serve' or 'systemctl start ollama') and re-run.\033[0m"
    exit 1
fi

# 2. Check for GGUF file in models/llm
GGUF_FILE=$(find "${GGUF_DIR}" -maxdepth 1 -name "*.gguf" | head -n 1)

if [ -z "${GGUF_FILE}" ]; then
    echo -e "\033[1;31m[X] No .gguf model file found in: ${GGUF_DIR}\033[0m"
    echo -e "\033[1;33m    Please place your downloaded .gguf file into: ${GGUF_DIR}\033[0m"
    exit 1
fi

GGUF_FILENAME=$(basename "${GGUF_FILE}")
echo -e "\033[1;32m[OK] Found GGUF file: ${GGUF_FILENAME}\033[0m"

# Update Modelfile FROM line
sed -i "s|^FROM .*|FROM ./${GGUF_FILENAME}|g" "${MODELFILE}"

# 3. Create Ollama Model
echo -e "\n\033[1;36m[*] Registering '${MODEL_NAME}' in Ollama from ${MODELFILE}...\033[0m"
cd "${GGUF_DIR}"
ollama create "${MODEL_NAME}" -f Modelfile
cd "${SCRIPT_DIR}/.."

echo -e "\033[1;32m[OK] Model '${MODEL_NAME}' successfully registered in Ollama!\033[0m"

# 4. Quick Inference Test
echo -e "\n\033[1;36m[*] Running rapid test inference...\033[0m"
PAYLOAD='{
  "model": "'"${MODEL_NAME}"'",
  "prompt": "Attack Type: TCP SYN Flood\nComposite Threat Score: 0.95\nSource IP: 192.168.1.100\nDestination IP: 192.168.1.1\nProtocol: TCP\nFlow Duration: 0.05s\nRecent Events (last 5): SYN Flood@0.94\nBaseline Deviation: Critical",
  "stream": false
}'

curl -s -X POST "http://localhost:11434/api/generate" \
     -H "Content-Type: application/json" \
     -d "${PAYLOAD}" | grep -o '"response":".*"' | sed 's/"response":"//;s/"$//' || true

echo -e "\n\033[1;36m============================================================\033[0m"
echo -e "\033[1;33mNext Step: Ensure your .env contains:\033[0m"
echo -e "\033[1;32mOLLAMA_MODEL=${MODEL_NAME}\033[0m"
echo -e "\033[1;36m============================================================\033[0m"
