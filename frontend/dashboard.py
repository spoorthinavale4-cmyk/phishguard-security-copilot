import streamlit as st
import requests

API_URL = "https://phishguard-security-copilot.onrender.com/analyze-email"

st.title("PhishGuard Security Copilot")

email_text = st.text_area("Paste suspicious email content")

if st.button("Analyze Email"):

    if email_text.strip() == "":
        st.warning("Please paste email content")
    else:
        with st.spinner("Analyzing email..."):

            payload = {"email_text": email_text}

            response = requests.post(API_URL, json=payload)

            if response.status_code == 200:

                data = response.json()

                for item in data["analysis"]:

                    st.subheader("URL Analysis")

                    st.write("URL:", item["url"])
                    st.write("Prediction:", item["prediction"])
                    st.write("Confidence:", item["confidence"])
                    st.write("Risk Level:", item["risk_level"])

                    st.write("Signals:", ", ".join(item["signals"]))

                    st.write("Decision:", item["decision_summary"])

                    st.write("Explanation:")
                    st.write(item["explanation"])

            else:
                st.error("API request failed")