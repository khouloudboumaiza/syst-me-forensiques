import requests
key = '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'
payload = {'model': 'qwen/qwen3.5-397b-a17b', 'messages': [{'role': 'user', 'content': 'dis bonjour'}], 'max_tokens': 50}
headers = {'Authorization': f'Bearer {key}', 'Accept': 'application/json', 'Content-Type': 'application/json'}
r = requests.post('https://integrate.api.nvidia.com/v1/chat/completions', headers=headers, json=payload, timeout=(10, 30))
print('status', r.status_code)
print(r.text)
