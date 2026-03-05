import streamlit as st
import requests


st.write("STREAMLIT APP STARTED")

API_URL = "https://phishguard-security-copilot.onrender.com/analyze_email"

st.set_page_config(page_title="PhishGuard Security Copilot")

st.title("🛡️ PhishGuard Security Copilot")
st.write("Paste an email below to detect phishing links.")

email_text = st.text_area("Email Content")

if st.button("Analyze Email"):

    if not email_text.strip():
        st.warning("Please paste an email first.")
    else:
        with st.spinner("Analyzing email..."):

            try:
                response = requests.post(
                    API_URL,
                    json={"text": email_text},
                    timeout=60
                )

                result = response.json()

                st.subheader("Analysis Result")
                st.json(result)

            except Exception as e:
                st.error(f"Error connecting to API: {e}")