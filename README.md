<div align="center">

# 🛡️ NetShield IDS

### ML-Based Network Intrusion Detection System

A production-grade intrusion detection system powered by **Random Forest** & **XGBoost**, featuring a real-time cyberpunk dashboard built with Flask. Trained on the **NSL-KDD** benchmark dataset with SMOTE-balanced classes.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0-FF6600?style=for-the-badge&logo=xgboost&logoColor=white)](https://xgboost.readthedocs.io)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Chart.js](https://img.shields.io/badge/Chart.js-4.x-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)](https://www.chartjs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00D4FF?style=for-the-badge)](LICENSE)

**[Features](#-features) · [Quick Start](#-quick-start) · [Model Performance](#-model-performance) · [Architecture](#%EF%B8%8F-architecture) · [Dashboard](#-dashboard) · [Tech Stack](#-tech-stack)**

</div>

---

## 🎬 Dashboard Preview

> 💡 **To add your own screenshots:** Take a screenshot of each page, save them in a `screenshots/` folder, and replace the paths below.

| Dashboard | Models | Alerts |
|:---------:|:------:|:------:|
| Real-time traffic feed with live attack detection | Model comparison with radar & bar charts | Filterable threat log with confidence scores |

---

## ✨ Features

### 🧠 Machine Learning Pipeline

| Feature | Description |
|---------|-------------|
| **Multi-Model Comparison** | Random Forest vs XGBoost vs LSTM (optional) side-by-side evaluation |
| **5-Class Classification** | Normal, DoS, Probe, R2L, U2R attack detection |
| **SMOTE Oversampling** | Handles extreme class imbalance (52 U2R vs 67K Normal samples) |
| **122 Engineered Features** | One-hot encoded protocols/services + scaled numeric features |
| **Automated Pipeline** | Single command trains all models, generates metrics, plots & reports |

### 🖥️ Real-Time Dashboard

| Feature | Description |
|---------|-------------|
| **Live Traffic Feed** | Server-Sent Events (SSE) stream with color-coded attack detection |
| **Interactive Charts** | Donut, line, radar, and bar charts powered by Chart.js |
| **3D Holographic Cards** | Mouse-following perspective tilt with light shine effect |
| **Particle Network** | Animated canvas background with connected nodes |
| **Toast Notifications** | Slide-in alerts when attacks are detected |
| **Dark / Light Mode** | Toggle with smooth transitions, preference saved in localStorage |
| **Keyboard Shortcuts** | Press `?` to see all shortcuts (1/2/3 navigate, T theme, F fullscreen) |
| **Fullscreen Mode** | Press `F` for immersive monitoring |
| **Sound Alerts** | Cyberpunk 3-tone audio alert on attack detection (Press `S`) |
| **CSV Export** | Download alert history as CSV (Press `E`) |
| **System Status Bar** | Live packets/s, threat count, connection status |
| **Threat Level Gauge** | Animated sidebar gauge showing current threat severity |
| **Glitch Text Effect** | Cyberpunk glitch animation on branding |
| **Scan Line** | Horizontal laser sweep overlay |
| **Live Clock & Uptime** | Real-time clock and session uptime counter |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- macOS / Linux / Windows
- `libomp` for XGBoost on macOS: `brew install libomp`

### 1. Clone & Setup

```bash
git clone https://github.com/yashh127/ML-Based-Intrusion-detection-system.git
cd ML-Based-Intrusion-detection-system

python3 -m venv venv
source venv/bin/activate       # macOS/Linux
# venv\Scripts\activate        # Windows

pip install -r requirements.txt
```

### 2. Download Dataset

```bash
mkdir -p data/raw
curl -L -o data/raw/KDDTrain+.txt "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt"
curl -L -o data/raw/KDDTest+.txt "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt"
```

### 3. Train Models

```bash
python train.py --mode multi     # 5-class classification (~45 seconds)
# python train.py --mode binary  # Normal vs Attack
# python train.py --mode all     # Both modes
```

### 4. Launch Dashboard

```bash
python run.py --demo --port 8080
```

Open **http://localhost:8080** → Done! 🎉

> The dashboard works even without trained models — it uses mock data as fallback.

---

## 📊 Model Performance

Evaluated on the **NSL-KDD Test+** set (contains novel attack types not seen in training):

| Model | Accuracy | Precision | Recall | F1 Score | Training Time |
|:------|:--------:|:---------:|:------:|:--------:|:-------------:|
| **Random Forest** | 75.15% | 81.48% | 75.15% | 71.30% | 18s |
| **XGBoost** ⭐ | 77.59% | 82.69% | 77.59% | 74.46% | 22s |

### Per-Class Breakdown (XGBoost)

| Attack Type | Precision | Recall | F1 Score | Support |
|:------------|:---------:|:------:|:--------:|:-------:|
| ✅ Normal | 67.6% | 97.2% | 79.8% | 9,711 |
| 🔴 DoS | 96.4% | 79.0% | 86.9% | 7,460 |
| 🟡 Probe | 84.7% | 69.2% | 76.2% | 2,421 |
| 🟣 R2L | 57.8% | 26.3% | 36.2% | 2,754 |
| 🔵 U2R | 42.6% | 10.1% | 16.3% | 200 |

> **Note:** Validation accuracy was 99.97%. Lower test accuracy is by design — NSL-KDD's test set contains **novel attack types** to test real-world generalization. These results are consistent with published benchmarks.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      DATA LAYER                             │
│  NSL-KDD (125K train / 22K test) → Preprocessing Pipeline  │
│  One-hot encoding → StandardScaler → SMOTE Oversampling     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    ML LAYER                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │ Random Forest│ │   XGBoost    │ │   LSTM (Optional)    │ │
│  │ 200 trees    │ │ 300 rounds   │ │ 128→64 units         │ │
│  │ max_depth=20 │ │ depth=8      │ │ Dropout 0.3          │ │
│  └──────┬───────┘ └──────┬───────┘ └──────────┬───────────┘ │
│         └────────────────┼────────────────────┘             │
└──────────────────────────┼──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                   APPLICATION LAYER                          │
│  Flask Backend → SSE Real-time Feed → REST API              │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐ │
│  │Dashboard │  │  Models  │  │  Alerts   │  │ API/Export  │ │
│  │Live Feed │  │Comparison│  │  History  │  │ CSV/JSON   │ │
│  └─────────┘  └──────────┘  └───────────┘  └────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|:---:|--------|
| `1` | Go to Dashboard |
| `2` | Go to Models |
| `3` | Go to Alerts |
| `T` | Toggle Dark/Light Mode |
| `F` | Toggle Fullscreen |
| `S` | Toggle Sound Alerts |
| `E` | Export Alerts to CSV |
| `?` | Show Shortcuts Help |

---

## 📁 Project Structure

```
ML-Based-Intrusion-detection-system/
├── 📂 data/
│   ├── raw/                    # NSL-KDD dataset files
│   └── processed/              # Preprocessed pickle caches
├── 📂 models/saved/
│   ├── rf_multi.joblib         # Trained Random Forest
│   ├── xgb_multi.joblib        # Trained XGBoost
│   ├── metrics.json            # Evaluation metrics for dashboard
│   └── plots/                  # Confusion matrices, ROC curves
├── 📂 src/
│   ├── data_pipeline.py        # Load, encode, scale NSL-KDD
│   ├── feature_engineering.py  # SMOTE, correlation filter, importance
│   ├── train_models.py         # RF, XGBoost, LSTM training logic
│   ├── evaluate.py             # Metrics, confusion matrices, ROC curves
│   ├── predict.py              # Real-time inference pipeline
│   └── packet_capture.py       # Scapy capture + demo replay
├── 📂 app/
│   ├── app.py                  # Flask application factory
│   ├── routes.py               # API endpoints + page routes
│   ├── templates/              # Jinja2 HTML (base, dashboard, models, alerts)
│   └── static/
│       ├── css/style.css       # 1900+ lines of premium cyberpunk CSS
│       └── js/dashboard.js     # 1300+ lines of interactive JS
├── train.py                    # CLI training entry point
├── run.py                      # Flask server entry point
└── requirements.txt
```

---

## 🔑 Tech Stack

| Category | Technologies |
|----------|-------------|
| **Machine Learning** | Scikit-learn, XGBoost, TensorFlow/Keras (optional) |
| **Data Processing** | Pandas, NumPy, imbalanced-learn (SMOTE) |
| **Networking** | Scapy (packet capture & feature extraction) |
| **Backend** | Flask, Server-Sent Events (SSE) |
| **Frontend** | Chart.js 4.x, Web Audio API, CSS3 Animations |
| **Visualization** | Matplotlib, Seaborn (training plots) |

---

## 🎯 Interview Talking Points

This project demonstrates proficiency across multiple domains:

1. **Machine Learning** — Multi-class classification, SMOTE oversampling, model comparison, hyperparameter tuning
2. **Data Engineering** — ETL pipeline, feature encoding, data normalization, train/test splitting
3. **Network Security** — NSL-KDD dataset, attack taxonomy (DoS/Probe/R2L/U2R), packet analysis with Scapy
4. **Full-Stack Development** — Flask backend, REST APIs, SSE real-time streaming, responsive UI
5. **Frontend Engineering** — CSS3 glassmorphism, Canvas particle system, Web Audio API, Chart.js, keyboard shortcuts
6. **Software Engineering** — Modular architecture, error handling, logging, CLI tools, fault-tolerant training

---

## 📝 License

MIT License — free for personal and commercial use.

---

<div align="center">

**Built with ❤️ by [yashh127](https://github.com/yashh127)**

*If you found this useful, give it a ⭐!*

</div>
