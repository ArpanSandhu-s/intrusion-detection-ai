
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import plotly.express as px

# 1. Setup Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Load Models with Fixed Paths
@st.cache_resource
def load_models():
    bin_mod = joblib.load(os.path.join(BASE_DIR, "models", "xgb_binary.pkl"))
    mul_mod = joblib.load(os.path.join(BASE_DIR, "models", "best_model.pkl"))
    s_bin   = joblib.load(os.path.join(BASE_DIR, "models", "scaler_binary.pkl"))
    s_mul   = joblib.load(os.path.join(BASE_DIR, "models", "scaler.pkl"))
    le      = joblib.load(os.path.join(BASE_DIR, "models", "label_encoder.pkl"))
    ce      = joblib.load(os.path.join(BASE_DIR, "models", "cat_encoders.pkl"))
    return bin_mod, mul_mod, s_bin, s_mul, le, ce

(binary_model, multi_model, scaler_bin, scaler_multi, label_encoder, cat_encoders) = load_models()

# 3. UI Header
st.title("🔐 AI Intrusion Detection System")
st.success("Models loaded successfully!")

# 4. Input Fields
col1, col2 = st.columns(2)
with col1:
    proto = st.selectbox("Protocol", ["tcp", "udp", "icmp"])
    state = st.selectbox("State", ["FIN", "INT", "CON", "REQ", "RST"])
    dur = st.number_input("Duration (s)", value=0.05)
with col2:
    service = st.selectbox("Service", ["http", "ftp", "smtp", "dns", "ssh", "-"])
    sbytes = st.number_input("Source Bytes", value=100)
    dbytes = st.number_input("Dest Bytes", value=200)

# 5. Prediction Logic
if st.button("Analyze Traffic", type="primary"):
    # Create matching feature vector (shortened for example, ensure all 34 match training)
    # This is a simplified version of your prediction logic
    st.info("Analyzing...")
    # ... (Rest of your prediction and chart logic from Cell 9) ...
    st.metric("Status", "Normal" if dur > 0 else "Attack")
