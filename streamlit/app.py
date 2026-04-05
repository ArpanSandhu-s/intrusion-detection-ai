
import streamlit as st
import joblib
import os
import pandas as pd

# This tells Python exactly where app.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@st.cache_resource
def load_models():
    # Use os.path.join to create absolute paths that work on any server
    binary_model   = joblib.load(os.path.join(BASE_DIR, "models", "xgb_binary.pkl"))
    multi_model    = joblib.load(os.path.join(BASE_DIR, "models", "best_model.pkl"))
    scaler_bin     = joblib.load(os.path.join(BASE_DIR, "models", "scaler_binary.pkl"))
    scaler_multi   = joblib.load(os.path.join(BASE_DIR, "models", "scaler.pkl"))
    label_encoder  = joblib.load(os.path.join(BASE_DIR, "models", "label_encoder.pkl"))
    cat_encoders   = joblib.load(os.path.join(BASE_DIR, "models", "cat_encoders.pkl"))
    
    return (binary_model, multi_model, scaler_bin, 
            scaler_multi, label_encoder, cat_encoders)

# Load them once
(binary_model, multi_model, scaler_bin, 
 scaler_multi, label_encoder, cat_encoders) = load_models()

st.success("Models loaded successfully!")
# ... rest of your UI code ...
