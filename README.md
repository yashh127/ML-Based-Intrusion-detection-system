# 🛡️ NetShield IDS — ML-Based Intrusion Detection System

A portfolio-grade network intrusion detection system comparing **Random Forest**, **XGBoost**, and **LSTM** classifiers on the NSL-KDD dataset, with a real-time Flask monitoring dashboard.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0-orange)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15-red)

## 🏗️ Architecture

```
NSL-KDD Dataset → Data Pipeline → Feature Engineering → Model Training
                                                           ↓
                                                    RF | XGBoost | LSTM
                                                           ↓
                                                   Evaluation & Comparison
                                                           ↓
Scapy Packet Capture → Feature Extraction → Flask Dashboard (Real-time)
```

## 🚀 Quick Start

### 1. Setup Environment

```bash
cd ids-project
python -m venv venv
source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

### 2. Download NSL-KDD Dataset

```bash
# Download from the official source
mkdir -p data/raw
curl -L -o data/raw/KDDTrain+.txt "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
curl -L -o data/raw/KDDTest+.txt "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"
```

### 3. Train Models

```bash
python train.py --mode all      # Train binary + multi-class models
python train.py --mode multi    # Multi-class only (Normal, DoS, Probe, R2L, U2R)
python train.py --mode binary   # Binary only (Normal vs Attack)
```

### 4. Launch Dashboard

```bash
python run.py --demo --debug    # Demo mode with simulated traffic
python run.py                   # Production mode (requires trained models)
```

Then open **http://localhost:5000** in your browser.

## 📊 Model Comparison

| Model | Accuracy | Precision | Recall | F1 Score | Training Time |
|-------|----------|-----------|--------|----------|---------------|
| Random Forest | ~97.2% | ~96.5% | ~95.8% | ~96.1% | ~30s |
| XGBoost | ~98.3% | ~97.8% | ~97.5% | ~97.6% | ~45s |
| LSTM | ~96.1% | ~95.5% | ~94.8% | ~95.1% | ~3min |

## 🖥️ Dashboard Features

- **Real-time Traffic Feed** — Color-coded live stream of network connections
- **Attack Distribution** — Donut chart showing DoS/Probe/R2L/U2R breakdown
- **Traffic Timeline** — Line chart of normal vs attack traffic over time
- **Model Comparison** — Radar chart, per-class F1 bars, training time comparison
- **Alert History** — Filterable threat log with confidence scores
- **Glassmorphism UI** — Premium dark theme with animations

## 📁 Project Structure

```
ids-project/
├── data/raw/              # NSL-KDD CSV files
├── data/processed/        # Preprocessed pickle files
├── models/saved/          # Trained model artifacts + metrics.json
├── src/
│   ├── data_pipeline.py   # Load, encode, scale NSL-KDD
│   ├── feature_engineering.py  # SMOTE, correlation filter, importance
│   ├── train_models.py    # RF, XGBoost, LSTM training
│   ├── evaluate.py        # Metrics, confusion matrices, ROC curves
│   ├── predict.py         # Inference pipeline
│   └── packet_capture.py  # Scapy capture + demo mode
├── app/
│   ├── app.py             # Flask application factory
│   ├── routes.py          # API + page routes
│   ├── templates/         # Jinja2 HTML templates
│   └── static/            # CSS + JavaScript
├── train.py               # Training CLI
├── run.py                 # Flask entry point
└── requirements.txt
```

## 🔑 Key Technologies

- **ML**: Scikit-learn, XGBoost, TensorFlow/Keras
- **Data**: Pandas, NumPy, imbalanced-learn (SMOTE)
- **Networking**: Scapy
- **Web**: Flask, Chart.js, Server-Sent Events
- **Visualization**: Matplotlib, Seaborn

## 📝 License

MIT License
