import os, traceback
from ai_explainer import explain_alert, _call_nvidia_chat, NVIDIA_API_KEY, NVIDIA_BASE_URL, NVIDIA_MODEL
import requests

print('PYTHON:', os.sys.version)
print('Requests:', getattr(requests, '__version__', 'missing'))
print('NVIDIA_API_KEY present:', bool(NVIDIA_API_KEY))
print('NVIDIA_BASE_URL:', NVIDIA_BASE_URL)
print('NVIDIA_MODEL:', NVIDIA_MODEL)

prompt = 'Test: Explique en une phrase ce que signifie cette alerte pour la colonne cible.'
try:
    print('\nCalling explain_alert(...)')
    res = explain_alert('TestRule', '192.0.2.1', 'loki', 'détails de test', 'high')
    print('explain_alert ->', res)
except Exception:
    print('explain_alert exception:')
    traceback.print_exc()

try:
    print('\nCalling _call_nvidia_chat(...) raw')
    raw = _call_nvidia_chat(prompt, temperature=0.2, max_tokens=80)
    print('raw result repr:', repr(raw))
except Exception:
    print('raw exception:')
    traceback.print_exc()
