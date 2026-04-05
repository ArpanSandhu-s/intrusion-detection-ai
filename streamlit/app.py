
import streamlit as st
import joblib
import os

# Define the base path relative to this script
BASE_DIR = os.path.dirname(__file__)

@st.cache_resource
def load_models():
    # Use os.path.join to point exactly to the streamlit/models/ folder
    binary_model = joblib.load(os.path.join(BASE_DIR, "models/xgb_binary.pkl"))
    multi_model  = joblib.load(os.path.join(BASE_DIR, "models/best_model.pkl"))
    scaler_bin   = joblib.load(os.path.join(BASE_DIR, "models/scaler_binary.pkl"))
    scaler_multi = joblib.load(os.path.join(BASE_DIR, "models/scaler.pkl"))
    return binary_model, multi_model, scaler_bin, scaler_multi

# ... the rest of your app code below ...
