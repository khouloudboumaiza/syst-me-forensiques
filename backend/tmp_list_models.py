import requests
headers = {
    "Authorization": "Bearer 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",
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
