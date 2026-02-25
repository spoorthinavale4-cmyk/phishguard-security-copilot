import requests

api_key = "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"

response = requests.get(
    "https://openrouter.ai/api/v1/models",
    headers={"Authorization": f"Bearer {api_key}"}
)

models = response.json()["data"]

# Filter only free models
free_models = [m["id"] for m in models if ":free" in m["id"]]

for m in free_models:
    print(m)