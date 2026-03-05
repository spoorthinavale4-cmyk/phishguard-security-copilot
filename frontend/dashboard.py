import streamlit as st
import requests

st.set_page_config(page_title="PhishGuard Security Copilot")

st.title("🛡️ PhishGuard Security Copilot")
st.write("Paste an email below to detect phishing links.")

API_URL = "https://phishguard-security-copilot.onrender.com/analyze-email"

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

                # Show raw response first
                st.write("Raw Response:")
                st.text(response.text)

                if response.status_code == 200:

                    try:
                        result = response.json()

                        st.subheader("Analysis Result")
                        st.json(result)

                    except Exception:
                        st.error("Response was not valid JSON.")

                else:
                    st.error("API returned an error")

            except Exception as e:
                st.error(f"Connection error: {e}")