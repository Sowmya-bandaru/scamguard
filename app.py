"""ScamGuard demo app.   Run:  streamlit run app.py"""
import os
import subprocess
import sys

import joblib
import streamlit as st

from rules import check_rules, risk_level

st.set_page_config(page_title="ScamGuard", page_icon="🛡️")


BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "model.joblib")


@st.cache_resource
def load_model():
    # On a fresh server (e.g. Streamlit Cloud) there is no model yet, so train it once.
    if not os.path.exists(MODEL_PATH):
        subprocess.run([sys.executable, "train.py"], cwd=BASE, check=True)
    return joblib.load(MODEL_PATH)


model = load_model()

EXAMPLES = {
    "Fake KYC": "Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz",
    "Fake internship": "Congratulations! You are selected for an internship. Pay Rs 999 registration fee within 24 hours to confirm your offer letter.",
    "Hinglish scam": "Aapka account block ho jayega. Abhi OTP share karein aur KYC update karein.",
    "Genuine alert": "Rs 1,250 debited from your account ending 4821 via UPI. If not you, call your bank.",
}

st.title("🛡️ ScamGuard")
st.caption("Paste a message. We tell you if it looks like a scam, and why.")

if "msg" not in st.session_state:
    st.session_state["msg"] = ""

st.write("Try an example:")
cols = st.columns(len(EXAMPLES))
for col, (label, text) in zip(cols, EXAMPLES.items()):
    if col.button(label):
        st.session_state["msg"] = text

message = st.text_area("Message to check", key="msg", height=150)

if st.button("Check message", type="primary"):
    if not message.strip():
        st.warning("Please paste a message first.")
    else:
        prob = float(model.predict_proba([message.lower()])[0][1])
        hits = check_rules(message)
        rule_score = min(len(hits) / 3, 1.0)
        score = 0.6 * prob + 0.4 * rule_score
        level = risk_level(score)

        if level == "High":
            st.error(f"HIGH RISK - this looks like a scam (risk score {score:.0%})")
        elif level == "Medium":
            st.warning(f"MEDIUM RISK - be careful (risk score {score:.0%})")
        else:
            st.success(f"LOW RISK - no major scam signs found (risk score {score:.0%})")
        st.progress(min(score, 1.0))

        if hits:
            st.subheader("Why we flagged it")
            for category, reason in hits:
                st.markdown(f"- **{category}:** {reason}")
        else:
            st.write("No known warning signs were found by our rule checks.")

        if level != "Low":
            st.subheader("What to do")
            st.markdown(
                "- Do **not** click links or share any OTP, PIN or password.\n"
                "- Verify using the official app, website or number printed on your card.\n"
                "- If you lost money, call **1930** or report at **cybercrime.gov.in** immediately."
            )

        st.caption("ScamGuard is a prototype. It can make mistakes, so always verify through official channels.")
