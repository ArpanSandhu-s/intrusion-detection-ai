
import streamlit as st
import pandas as pd
import joblib
import os
import plotly.express as px

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@st.cache_resource
def load_models():
    bin_mod = joblib.load(os.path.join(BASE_DIR, "models", "xgb_binary.pkl"))
    mul_mod = joblib.load(os.path.join(BASE_DIR, "models", "best_model.pkl"))
    s_bin   = joblib.load(os.path.join(BASE_DIR, "models", "scaler_binary.pkl"))
    le      = joblib.load(os.path.join(BASE_DIR, "models", "label_encoder.pkl"))
    ce      = joblib.load(os.path.join(BASE_DIR, "models", "cat_encoders.pkl"))
    return bin_mod, mul_mod, s_bin, le, ce

(binary_model, multi_model, scaler_bin, label_encoder, cat_encoders) = load_models()

st.title("🔐 AI Intrusion Detection System")

# Sample Data Logic
if 'inputs' not in st.session_state:
    st.session_state.inputs = {'dur': 0.05, 'sbytes': 100, 'dbytes': 200, 'spkts': 2, 'dpkts': 3, 'state': 'FIN'}

col_btn1, col_btn2 = st.columns(2)
with col_btn1:
    if st.button("✅ Load Normal Sample"):
        st.session_state.inputs = {'dur': 0.05, 'sbytes': 100, 'dbytes': 200, 'spkts': 2, 'dpkts': 3, 'state': 'FIN'}
with col_btn2:
    if st.button("🚨 Load Attack Sample"):
        st.session_state.inputs = {'dur': 0.00001, 'sbytes': 50000, 'dbytes': 0, 'spkts': 100, 'dpkts': 0, 'state': 'INT'}

# --- FULL INPUT GRID ---
col1, col2, col3 = st.columns(3)
with col1:
    proto = st.selectbox("Protocol", ["tcp", "udp", "icmp"])
    sbytes = st.number_input("Source Bytes", value=st.session_state.inputs['sbytes'])
    spkts = st.number_input("Source Packets", value=st.session_state.inputs['spkts'])
with col2:
    service = st.selectbox("Service", ["http", "ftp", "smtp", "dns", "ssh", "-"])
    dbytes = st.number_input("Dest Bytes", value=st.session_state.inputs['dbytes'])
    dpkts = st.number_input("Dest Packets", value=st.session_state.inputs['dpkts'])
with col3:
    state = st.selectbox("State", ["FIN", "INT", "CON", "REQ", "RST"], 
                         index=["FIN", "INT", "CON", "REQ", "RST"].index(st.session_state.inputs['state']))
    dur = st.number_input("Duration (s)", value=st.session_state.inputs['dur'], format="%.5f")

if st.button("Analyze Traffic", type="primary"):
    # Create 34-feature vector
    payload = {"dur": dur, "proto": proto, "service": service, "state": state, "spkts": spkts, "dpkts": dpkts, "sbytes": sbytes, "dbytes": dbytes}
    input_df = pd.DataFrame([payload])
    
    # Fill remaining 26 features with 0 to match model training
    for col in [c for c in cat_encoders.keys() if c not in input_df.columns]:
        input_df[col] = 0
    # (Simplified for space: ensure all 34 features exist here)
    
    # AI Prediction
    for col in ["proto", "service", "state"]:
        input_df[col] = cat_encoders[col].transform(input_df[col].astype(str))
    
    # (Note: Manually adding missing columns here for demo)
    missing_cols = [c for c in cat_encoders.keys() if c not in input_df.columns]
    # ... logic to align columns ...

    scaled = scaler_bin.transform(input_df) # This requires all 34 features
    is_attack = binary_model.predict(scaled)[0]
    
    if is_attack == 1:
        st.error("🚨 ATTACK DETECTED")
        # Logic for Plotly Chart...
    else:
        st.success("✅ Traffic is Normal")
