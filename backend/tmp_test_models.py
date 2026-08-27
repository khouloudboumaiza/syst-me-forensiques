import requests, json
import os
from dotenv import load_dotenv
load_dotenv()
API_KEY = os.environ.get("NVIDIA_API_KEY", "")
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# Test multiple models to find the fastest working one
models_to_test = [
    "nvidia/llama-3.1-nemotron-51b-instruct",
    "meta/llama-3.2-11b-vision-instruct",
    "mistralai/mistral-7b-instruct-v0.3",
    "deepseek-ai/deepseek-v4-flash-0731",
]

for model in models_to_test:
    print(f"\n--- Testing {model} ---")
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Explique en une phrase ce qu'est un C2 beacon en cybersécurité."}],
        "max_tokens": 100,
        "temperature": 0.6,
        "stream": False,
    }
    try:
        import time
        t0 = time.time()
        resp = requests.post("https://integrate.api.nvidia.com/v1/chat/completions", headers=headers, json=payload, timeout=(10, 30))
        elapsed = time.time() - t0
        print(f"  Status: {resp.status_code} in {elapsed:.1f}s")
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            print(f"  Response: {str(content)[:200]}")
            break  # Stop at first working model
        else:
            print(f"  Error: {resp.text[:200]}")
    except Exception as e:
        print(f"  Exception: {type(e).__name__}: {e}")
