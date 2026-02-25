import streamlit as st
import requests

st.title("🛡️ PhishGuard Security Copilot")

email_text = st.text_area("Paste email content containing URLs:")

if st.button("Analyze"):

    payload = {"email_text": email_text}

    try:
        response = requests.post(
            "http://127.0.0.1:9000/analyze-email",
            json=payload
        )

        data = response.json()
        st.json(data)

    except Exception as e:
        st.error(str(e))