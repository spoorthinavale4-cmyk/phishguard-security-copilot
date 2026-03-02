import os
import time
import sys
import threading
from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("OPENROUTER_API_KEY")

if not API_KEY:
    raise RuntimeError("OPENROUTER_API_KEY not found. Check your .env file.")



def loading_spinner(stop_event):
    while not stop_event.is_set():
        for c in "|/-\\":
            sys.stdout.write(f"\r Analyzing... {c}")
            sys.stdout.flush()
            time.sleep(0.1)
            if stop_event.is_set():
                break
    sys.stdout.write("\r Analysis complete!     \n")
    sys.stdout.flush()



def generate_llm_explanation(url, prediction, confidence):

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

    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=loading_spinner, args=(stop_event,))
    spinner_thread.start()

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

        stop_event.set()
        spinner_thread.join()

        
        if response and hasattr(response, "choices") and len(response.choices) > 0:
            message = response.choices[0].message
            if message and hasattr(message, "content"):
                return message.content

        print("OpenRouter returned unexpected response:", response)
        return f"Automated risk assessment: {prediction.upper()} risk with {round(confidence*100)}% confidence."

    except Exception as e:
        stop_event.set()
        spinner_thread.join()
        print("LLM ERROR:", str(e))


        return f"""
Enterprise Risk Summary:
Prediction: {prediction.upper()}
Confidence: {round(confidence*100)}%

The AI explanation service is temporarily unavailable.
Risk classification is generated from the phishing detection model.
"""
