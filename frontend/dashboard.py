import streamlit as st
import requests

st.set_page_config(page_title="PhishGuard Security Copilot")

st.write("STREAMLIT APP STARTED")

API_URL = "https://phishguard-security-copilot.onrender.com/analyze-email"

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
                    json={"email_text": email_text},
                    timeout=60
                )

                st.write("Status Code:", response.status_code)
                st.write("Raw Response:", response.text)

                if response.status_code == 200:
                    result = response.json()

                    st.subheader("Analysis Result")
                    st.json(result)

                else:
                    st.error("API returned an error")

            except Exception as e:
                st.error(f"Error connecting to API: {e}")