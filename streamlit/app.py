
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import plotly.express as px
import plotly.graph_objects as go

# ── Page config ──────────────────────────────────────
st.set_page_config(
    page_title="AI Intrusion Detection System",
    page_icon="🔐",
    layout="wide"
)

# ── Load models ───────────────────────────────────────
@st.cache_resource
def load_models():
    binary_model  = joblib.load("models/xgb_binary.pkl")
    multi_model   = joblib.load("models/best_model.pkl")
    scaler_bin    = joblib.load("models/scaler_binary.pkl")
    scaler_multi  = joblib.load("models/scaler.pkl")
    label_encoder = joblib.load("models/label_encoder.pkl")
    cat_encoders  = joblib.load("models/cat_encoders.pkl")
    return (binary_model, multi_model, scaler_bin,
            scaler_multi, label_encoder, cat_encoders)

(binary_model, multi_model, scaler_bin,
 scaler_multi, label_encoder, cat_encoders) = load_models()

FEATURE_COLS = [
    "dur","proto","service","state","spkts","dpkts",
    "sbytes","dbytes","rate","sload","dload","sloss",
    "dloss","sinpkt","dinpkt","sjit","djit","swin",
    "stcpb","dtcpb","dwin","tcprtt","synack","ackdat",
    "smean","dmean","trans_depth","response_body_len",
    "ct_src_dport_ltm","ct_dst_sport_ltm","is_ftp_login",
    "ct_ftp_cmd","ct_flw_http_mthd","is_sm_ips_ports"
]

def preprocess(data):
    df = pd.DataFrame([data])
    for col in ["proto", "service", "state"]:
        le  = cat_encoders[col]
        val = str(df[col].iloc[0])
        df[col] = le.transform([val]) if val in le.classes_ else [0]
    return df[FEATURE_COLS].astype(float)

def predict_full(data):
    df           = preprocess(data)
    bin_sc       = scaler_bin.transform(df)
    bin_pred     = binary_model.predict(bin_sc)[0]
    bin_proba    = binary_model.predict_proba(bin_sc)[0]
    multi_sc     = scaler_multi.transform(df)
    multi_pred   = multi_model.predict(multi_sc)[0]
    multi_proba  = multi_model.predict_proba(multi_sc)[0]
    attack_type  = label_encoder.inverse_transform([multi_pred])[0]
    return {
        "is_attack"  : bool(bin_pred == 1),
        "prediction" : "Attack" if bin_pred == 1 else "Normal",
        "confidence" : round(float(bin_proba[bin_pred]) * 100, 2),
        "threat_level": (
            "HIGH"   if bin_proba[bin_pred] >= 0.9 and bin_pred == 1
            else "MEDIUM" if bin_proba[bin_pred] >= 0.7 and bin_pred == 1
            else "LOW"    if bin_pred == 1 else "NONE"
        ),
        "attack_type": attack_type,
        "type_conf"  : round(float(multi_proba[multi_pred]) * 100, 2),
        "all_probs"  : {
            label_encoder.inverse_transform([i])[0]: round(float(p)*100, 2)
            for i, p in enumerate(multi_proba)
        }
    }

# ── Header ────────────────────────────────────────────
st.markdown("""
<div style="background:#0d1224;padding:20px 30px;
     border-radius:10px;margin-bottom:24px;
     border:1px solid #1e2d4a">
  <h1 style="color:#fff;margin:0;font-size:24px">
    🔐 AI Intrusion Detection System
  </h1>
  <p style="color:#4a6fa5;margin:4px 0 0">
    UNSW-NB15 · XGBoost · 99% AUC · Real-time Detection
  </p>
</div>
""", unsafe_allow_html=True)

# ── Tabs ─────────────────────────────────────────────
tab1, tab2 = st.tabs(["🔍 Single Prediction", "📂 Batch CSV Upload"])

# ───────────────────────────────────────────────────
# TAB 1 — Single prediction
# ───────────────────────────────────────────────────
with tab1:
    st.subheader("Analyze a Network Connection")

    col1, col2, col3 = st.columns(3)
    with col1:
        proto   = st.selectbox("Protocol", ["tcp","udp","icmp"])
        sbytes  = st.number_input("Src Bytes", value=100)
        spkts   = st.number_input("Src Packets", value=2)
    with col2:
        service = st.selectbox("Service",
                    ["http","ftp","smtp","dns","ssh","-"])
        dbytes  = st.number_input("Dst Bytes", value=200)
        dpkts   = st.number_input("Dst Packets", value=3)
    with col3:
        state   = st.selectbox("State",
                    ["FIN","INT","CON","REQ","RST"])
        dur     = st.number_input("Duration (s)",
                    value=0.05, step=0.01)

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        predict_btn = st.button("🔍 Analyze", type="primary",
                                use_container_width=True)
    with col_b:
        if st.button("✅ Load Normal Sample",
                     use_container_width=True):
            st.session_state.sample = "normal"
    with col_c:
        if st.button("🚨 Load Attack Sample",
                     use_container_width=True):
            st.session_state.sample = "attack"

    if predict_btn:
        payload = {
            "dur": dur, "proto": proto, "service": service,
            "state": state, "spkts": int(spkts),
            "dpkts": int(dpkts), "sbytes": int(sbytes),
            "dbytes": int(dbytes),
            **{k: 0 for k in FEATURE_COLS
               if k not in ["dur","proto","service","state",
                            "spkts","dpkts","sbytes","dbytes"]}
        }

        result = predict_full(payload)

        # Result display
        if result["is_attack"]:
            st.error(f"⚠️ ATTACK DETECTED — "
                     f"{result['attack_type']} "
                     f"({result['confidence']}% confidence)")
        else:
            st.success(f"✅ NORMAL TRAFFIC "
                       f"({result['confidence']}% confidence)")

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Prediction",  result["prediction"])
        m2.metric("Confidence",  f"{result['confidence']}%")
        m3.metric("Attack Type", result["attack_type"])
        m4.metric("Threat Level",result["threat_level"])

        # Probability bar chart
        st.subheader("Probability per Attack Category")
        probs_df = pd.DataFrame(
            list(result["all_probs"].items()),
            columns=["Category", "Probability %"]
        ).sort_values("Probability %", ascending=True)

        fig = px.bar(
            probs_df, x="Probability %", y="Category",
            orientation="h", color="Probability %",
            color_continuous_scale="RdYlGn_r",
            title="Model confidence per category"
        )
        fig.update_layout(
            plot_bgcolor="#0d1224",
            paper_bgcolor="#0d1224",
            font_color="#e0e6f0",
            height=350
        )
        st.plotly_chart(fig, use_container_width=True)

# ───────────────────────────────────────────────────
# TAB 2 — Batch CSV upload
# ───────────────────────────────────────────────────
with tab2:
    st.subheader("Upload CSV for Batch Analysis")
    st.info("Upload a CSV with the same columns as UNSW-NB15 "
            "training set. The model will predict each row.")

    uploaded = st.file_uploader("Choose CSV file", type="csv")

    if uploaded:
        df_upload = pd.read_csv(uploaded)
        st.write(f"Loaded {len(df_upload)} rows")
        st.dataframe(df_upload.head())

        if st.button("🔍 Run Batch Prediction", type="primary"):
            results = []
            progress = st.progress(0)

            for i, row in df_upload.iterrows():
                try:
                    payload = row.to_dict()
                    # Fill missing cols with 0
                    for col in FEATURE_COLS:
                        if col not in payload:
                            payload[col] = 0
                    r = predict_full(payload)
                    results.append({
                        "Row"         : i,
                        "Prediction"  : r["prediction"],
                        "Attack Type" : r["attack_type"],
                        "Confidence"  : f"{r['confidence']}%",
                        "Threat Level": r["threat_level"]
                    })
                except:
                    results.append({
                        "Row"         : i,
                        "Prediction"  : "Error",
                        "Attack Type" : "—",
                        "Confidence"  : "—",
                        "Threat Level": "—"
                    })
                progress.progress((i+1) / len(df_upload))

            results_df = pd.DataFrame(results)
            st.dataframe(results_df)

            # Summary chart
            attack_counts = results_df[
                results_df["Prediction"] == "Attack"
            ]["Attack Type"].value_counts()

            if len(attack_counts) > 0:
                fig2 = px.pie(
                    values=attack_counts.values,
                    names=attack_counts.index,
                    title="Attack Type Distribution",
                    color_discrete_sequence=px.colors.sequential.RdBu
                )
                fig2.update_layout(
                    plot_bgcolor="#0d1224",
                    paper_bgcolor="#0d1224",
                    font_color="#e0e6f0"
                )
                st.plotly_chart(fig2, use_container_width=True)

            # Download results
            csv = results_df.to_csv(index=False)
            st.download_button(
                "⬇️ Download Results CSV",
                csv,
                "ids_predictions.csv",
                "text/csv"
            )

# ── Footer ────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<p style='text-align:center;color:#4a6fa5;font-size:12px'>"
    "AI IDS · UNSW-NB15 · XGBoost · 99% AUC</p>",
    unsafe_allow_html=True
)
