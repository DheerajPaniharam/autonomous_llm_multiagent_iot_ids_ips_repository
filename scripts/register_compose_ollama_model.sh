#!/bin/sh
set -eu

MODEL_NAME="${OLLAMA_MODEL:-qwen2.5-3b-iot-ids}"

if ollama show "$MODEL_NAME" >/dev/null 2>&1; then
    echo "Ollama model already registered: $MODEL_NAME"
    exit 0
fi

if [ ! -f /models/Modelfile ]; then
    echo "Missing /models/Modelfile; mount models/llm into the Ollama initializer" >&2
    exit 1
fi

if [ ! -f /models/qwen2.5-3b-instruct.Q4_K_M.gguf ]; then
    echo "Missing fine-tuned GGUF: /models/qwen2.5-3b-instruct.Q4_K_M.gguf" >&2
    exit 1
fi

cd /models
ollama create "$MODEL_NAME" -f Modelfile