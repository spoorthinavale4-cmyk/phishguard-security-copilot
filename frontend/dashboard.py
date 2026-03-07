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


                if response.status_code == 200:

                    try:
                        result = response.json()

                        st.success("Analysis Complete")

                        if not result.get("analysis"):
                            st.info("No URLs found in the email.")
                        else:
                            for item in result["analysis"]:

                                st.subheader("🔍 URL Analysis")

                                st.write("**URL:**", item["url"])
                                st.write("**Prediction:**", item["prediction"])
                                st.write("**Confidence:**", round(item["confidence"], 2))
                                st.write("**Risk Level:**", item["risk_level"])

                                # Risk indicator
                                if item["risk_level"] == "high":
                                    st.error("🔴 HIGH RISK")
                                elif item["risk_level"] == "medium":
                                    st.warning("🟡 MEDIUM RISK")
                                else:
                                    st.success("🟢 SAFE")

                                st.write("**Signals:**", ", ".join(item["signals"]))

                                st.write("**Decision Summary:**")
                                st.info(item["decision_summary"])

                                st.write("**AI Explanation:**")
                                st.write(item["explanation"])

                                # SIEM alert section
                                if item.get("siem_alert"):
                                    st.subheader("⚠️ SIEM Alert")
                                    st.write(item["siem_alert"])

                                st.divider()

                    except Exception:
                        st.error("Response was not valid JSON.")

                else:
                    st.error("API returned an error")

            except Exception as e:
                st.error(f"Connection error: {e}")