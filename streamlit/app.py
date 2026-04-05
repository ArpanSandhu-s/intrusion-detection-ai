
import streamlit as st
import pandas as pd
import joblib
import os
import plotly.express as px

# 1. Setup Paths
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

# 2. Sample Loading Logic
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
        st.session_state.dur = 0.00001
        st.session_state.state = "INT"

# 3. Input UI
col1, col2 = st.columns(2)
with col1:
    proto = st.selectbox("Protocol", ["tcp", "udp", "icmp"])
    state = st.selectbox("State", ["FIN", "INT", "CON", "REQ", "RST"], 
                         index=["FIN", "INT", "CON", "REQ", "RST"].index(st.session_state.state))
with col2:
    service = st.selectbox("Service", ["http", "ftp", "smtp", "dns", "ssh", "-"])
    dur = st.number_input("Duration (s)", value=st.session_state.dur, format="%.5f")

# 4. Analyze Logic
if st.button("Analyze Traffic", type="primary"):
    # Create the full feature row (34 features)
    input_df = pd.DataFrame([{
        "dur": dur, "proto": proto, "service": service, "state": state,
        "spkts": 2, "dpkts": 0, "sbytes": 100, "dbytes": 0, "rate": 0,
        "sload": 0, "dload": 0, "sloss": 0, "dloss": 0, "sinpkt": 0,
        "dinpkt": 0, "sjit": 0, "djit": 0, "swin": 0, "stcpb": 0,
        "dtcpb": 0, "dwin": 0, "tcprtt": 0, "synack": 0, "ackdat": 0,
        "smean": 0, "dmean": 0, "trans_depth": 0, "response_body_len": 0,
        "ct_src_dport_ltm": 0, "ct_dst_sport_ltm": 0, "is_ftp_login": 0,
        "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "is_sm_ips_ports": 0
    }])
    
    # Encode and Scale
    for col in ["proto", "service", "state"]:
        input_df[col] = cat_encoders[col].transform(input_df[col].astype(str))
    
    scaled = scaler_bin.transform(input_df)
    
    # Predict
    is_attack = binary_model.predict(scaled)[0]
    multi_probs = multi_model.predict_proba(scaled)[0]
    
    # Display Result
    if is_attack == 1:
        st.error(f"🚨 ATTACK DETECTED")
        # Show specific attack types
        probs_df = pd.DataFrame({
            "Category": label_encoder.classes_,
            "Confidence": multi_probs * 100
        }).sort_values("Confidence", ascending=True)
        
        fig = px.bar(probs_df, x="Confidence", y="Category", orientation='h', title="Attack Probabilities")
        st.plotly_chart(fig)
    else:
        st.success("✅ Traffic is Normal")
