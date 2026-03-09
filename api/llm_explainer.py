import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()



def generate_llm_explanation(url, prediction, confidence):
    API_KEY = os.getenv("Groq_API_KEY")
    if not API_KEY:
        print("WARNING: Groq_API_KEY not set — LLM explanation skipped.")
        return f"Enterprise Risk Summary:\nPrediction: {prediction.upper()}\nConfidence: {round(confidence*100)}%\n\nAI explanation unavailable (API key not configured)."

    client = OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=API_KEY
    )

    prompt = f"""
You are a SOC analyst assistant.

STRICT RULES:
- The ML model prediction is FINAL.
- DO NOT contradict the prediction.
- If prediction = legitimate → risk level must be LOW.
- If prediction = phishing → risk level must be HIGH.
- You are ONLY explaining the model result, not re-analyzing the URL.

URL: {url}
Model Prediction: {prediction}
Confidence: {round(confidence*100,2)}%

Write a SHORT enterprise risk explanation aligned with the prediction.
"""

    try:
        response = client.chat.completions.create(
            model="moonshotai/kimi-k2-instruct-0905",

            messages=[
                {"role": "system", "content": "You are a professional SOC analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            timeout=15
        )

        if response and hasattr(response, "choices") and len(response.choices) > 0:
            message = response.choices[0].message
            if message and hasattr(message, "content"):
                return message.content

        print("LLM returned unexpected response:", response)
        return f"Automated risk assessment: {prediction.upper()} risk with {round(confidence*100)}% confidence."

    except Exception as e:
        print("LLM ERROR:", str(e))
        return f"""Enterprise Risk Summary:
Prediction: {prediction.upper()}
Confidence: {round(confidence*100)}%

The AI explanation service is temporarily unavailable.
Risk classification is generated from the phishing detection model.
"""
