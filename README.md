# 🔐 AI Intrusion Detection System

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit)](https://intrusion-detection-ai-hzv5kw8ggacqgaeqjf7h9u.streamlit.app/)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github)](https://github.com/ArpanSandhu-s/intrusion-detection-ai)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0-FF6600?style=for-the-badge)](https://xgboost.ai)

## 🚀 Overview
This project is a real-time Network Intrusion Detection System (NIDS) built using Machine Learning. It analyzes network traffic patterns to identify potential security threats such as DoS attacks, Exploits, and Fuzzers using the **UNSW-NB15** dataset.

## 📊 Project Visualizations
### Model Performance Comparison
![Results](outputs/07_final_results.png)

### Feature Importance (What the AI looks for)
![Features](outputs/09_feature_importance.png)

## 🛠️ Tech Stack
* **Language:** Python 3.11
* **ML Framework:** XGBoost, Scikit-Learn
* **Dashboard:** Streamlit, Plotly
* **Dataset:** UNSW-NB15 (175K+ records)

## 📈 Performance Summary
| Model Type | Accuracy | F1-Score | ROC-AUC |
| :--- | :--- | :--- | :--- |
| **Binary (Normal vs Attack)** | 94.17% | 95.43% | 98.99% |
| **Multiclass (Categorization)** | 82.41% | 54.91% (Macro) | - |

> **Note:** The Macro F1 score reflects the extreme class imbalance in real-world network data (e.g., very few "Worms" samples compared to "Normal" traffic), which is a common challenge in cybersecurity AI.

## 📁 Project Structure
* `streamlit/app.py`: The live dashboard code.
* `streamlit/models/`: Trained XGBoost model files and scalers.
* `outputs/`: Performance charts and evaluation plots.
* `requirements.txt`: Python dependency list for deployment.

## 📖 How to Test the AI
1. Visit the [Live Demo](https://intrusion-detection-ai-hzv5kw8ggacqgaeqjf7h9u.streamlit.app/).
2. Click **"🚨 Load Attack Sample"** to auto-fill the form with malicious parameters (high source bytes, specific protocol states).
3. Click **"Analyze Traffic"** to see the AI identify the threat and calculate confidence levels for different attack types.

---
Created by [ArpanSandhu-s](https://github.com/ArpanSandhu-s)
