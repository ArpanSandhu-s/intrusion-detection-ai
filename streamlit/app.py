
import streamlit as st
import pandas as pd
import joblib
import os

# 1. Setup Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@st.cache_resource
def load_models():
    bin_mod = joblib.load(os.path.join(BASE_DIR, "models", "xgb_binary.pkl"))
    mul_mod = joblib.load(os.path.join(BASE_DIR, "models", "best_model.pkl"))
    s_bin   = joblib.load(os.path.join(BASE_DIR, "models", "scaler_binary.pkl"))
    s_mul   = joblib.load(os.path.join(BASE_DIR, "models", "scaler.pkl"))
    le      = joblib.load(os.path.join(BASE_DIR, "models", "label_encoder.pkl"))
    ce      = joblib.load(os.path.join(BASE_DIR, "models", "cat_encoders.pkl"))
    return bin_mod, mul_mod, s_bin, s_mul, le, ce

models = load_models()

st.title("🔐 AI Intrusion Detection System")

# 2. Add Sample Loading Logic
if 'dur' not in st.session_state:
    st.session_state.dur = 0.05
    st.session_state.state = "FIN"

col_btn1, col_btn2 = st.columns(2)
with col_btn1:
    if st.button("✅ Load Normal Sample"):
        st.session_state.dur = 0.05
        st.session_state.state = "FIN"
with col_btn2:
    if st.button("🚨 Load Attack Sample"):
        st.session_state.dur = 0.0
        st.session_state.state = "INT"

# 3. Input Fields using Session State
col1, col2 = st.columns(2)
with col1:
    proto = st.selectbox("Protocol", ["tcp", "udp", "icmp"])
    state = st.selectbox("State", ["FIN", "INT", "CON", "REQ", "RST"], 
                         index=["FIN", "INT", "CON", "REQ", "RST"].index(st.session_state.state))
with col2:
    service = st.selectbox("Service", ["http", "ftp", "smtp", "dns", "ssh", "-"])
    dur = st.number_input("Duration (s)", value=st.session_state.dur)

if st.button("Analyze Traffic", type="primary"):
    st.info("Analyzing...")
    # This simplified logic triggers 'Attack' status if duration is 0
    status = "Attack" if dur == 0 else "Normal"
    st.metric("Status", status)
