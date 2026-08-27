import requests
import os
from dotenv import load_dotenv
load_dotenv()
headers = {
    "Authorization": f"Bearer {os.environ.get('NVIDIA_API_KEY', '')}",
    "Accept": "application/json",
}
resp = requests.get("https://integrate.api.nvidia.com/v1/models", headers=headers, timeout=(10, 30))
print("Status:", resp.status_code)
if resp.status_code == 200:
    data = resp.json()
    models = data.get("data", [])
    print(f"Found {len(models)} models")
    # Filter for chat/text models
    for m in models:
        mid = m.get("id", "?")
        if "qwen" in mid.lower() or "llama" in mid.lower() or "mistral" in mid.lower() or "deepseek" in mid.lower():
            print(f"  - {mid}")
else:
    print(resp.text[:500])
