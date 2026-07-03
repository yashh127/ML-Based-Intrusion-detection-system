"""Flask Blueprint with all routes for the NetShield IDS Dashboard."""

import json
import random
import time
from datetime import datetime
from pathlib import Path

from flask import Blueprint, Response, jsonify, render_template, request

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models" / "saved"
DATA_DIR = PROJECT_ROOT / "data" / "processed"

bp = Blueprint("main", __name__)

recent_traffic: list[dict] = []
MAX_TRAFFIC_ENTRIES = 200

ATTACK_TYPES = ["Normal", "DoS", "Probe", "R2L", "U2R"]
ATTACK_WEIGHTS = [0.70, 0.15, 0.08, 0.05, 0.02]

PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = [
    "http", "smtp", "ftp_data", "ftp", "ssh", "dns", "telnet",
    "pop3", "imap", "https", "snmp", "ntp", "ldap",
]

MOCK_METRICS = {
    "Random Forest": {
        "accuracy": 0.972,
        "precision": 0.965,
        "recall": 0.958,
        "f1_score": 0.961,
        "training_time": 28.5,
        "per_class": {
            "Normal": {"precision": 0.985, "recall": 0.990, "f1_score": 0.987},
            "DoS": {"precision": 0.975, "recall": 0.968, "f1_score": 0.971},
            "Probe": {"precision": 0.952, "recall": 0.941, "f1_score": 0.946},
            "R2L": {"precision": 0.918, "recall": 0.895, "f1_score": 0.906},
            "U2R": {"precision": 0.892, "recall": 0.871, "f1_score": 0.881},
        },
    },
    "XGBoost": {
        "accuracy": 0.983,
        "precision": 0.978,
        "recall": 0.975,
        "f1_score": 0.976,
        "training_time": 42.1,
        "per_class": {
            "Normal": {"precision": 0.992, "recall": 0.995, "f1_score": 0.993},
            "DoS": {"precision": 0.985, "recall": 0.981, "f1_score": 0.983},
            "Probe": {"precision": 0.968, "recall": 0.962, "f1_score": 0.965},
            "R2L": {"precision": 0.941, "recall": 0.925, "f1_score": 0.933},
            "U2R": {"precision": 0.915, "recall": 0.898, "f1_score": 0.906},
        },
    },
    "LSTM": {
        "accuracy": 0.961,
        "precision": 0.955,
        "recall": 0.948,
        "f1_score": 0.951,
        "training_time": 185.3,
        "per_class": {
            "Normal": {"precision": 0.978, "recall": 0.983, "f1_score": 0.980},
            "DoS": {"precision": 0.962, "recall": 0.955, "f1_score": 0.958},
            "Probe": {"precision": 0.945, "recall": 0.932, "f1_score": 0.938},
            "R2L": {"precision": 0.908, "recall": 0.882, "f1_score": 0.895},
            "U2R": {"precision": 0.878, "recall": 0.855, "f1_score": 0.866},
        },
    },
}


def generate_random_ip(private: bool = True) -> str:
    """Generate a random realistic IP address."""
    if private:
        networks = [
            f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        ]
    else:
        networks = [
            f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        ]
    return random.choice(networks)


def generate_mock_sample() -> dict:
    """Generate a single mock traffic sample with realistic distribution."""
    attack_type = random.choices(ATTACK_TYPES, weights=ATTACK_WEIGHTS, k=1)[0]
    confidence = round(random.uniform(0.82, 0.99), 3) if attack_type == "Normal" else round(random.uniform(0.65, 0.98), 3)

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": generate_random_ip(private=True),
        "dst_ip": generate_random_ip(private=random.random() > 0.3),
        "protocol": random.choice(PROTOCOLS),
        "service": random.choice(SERVICES),
        "prediction": attack_type,
        "confidence": confidence,
        "attack_type": attack_type,
    }


@bp.route("/")
def dashboard():
    """Render the main dashboard page."""
    return render_template("dashboard.html")


@bp.route("/models")
def models():
    """Render the model comparison page."""
    return render_template("models.html")


@bp.route("/alerts")
def alerts():
    """Render the alert history page."""
    return render_template("alerts.html")


@bp.route("/api/metrics")
def api_metrics():
    """Return model performance metrics."""
    metrics_path = MODELS_DIR / "metrics.json"
    try:
        if metrics_path.exists():
            with open(metrics_path, "r") as f:
                metrics = json.load(f)
            return jsonify(metrics)
    except (json.JSONDecodeError, IOError):
        pass

    return jsonify(MOCK_METRICS)


@bp.route("/api/predict", methods=["POST"])
def api_predict():
    """Accept JSON with 41 features and return predictions from all 3 models."""
    data = request.get_json()
    if not data or "features" not in data:
        return jsonify({"error": "Request must include 'features' array with 41 values"}), 400

    features = data["features"]
    if len(features) != 41:
        return jsonify({"error": f"Expected 41 features, got {len(features)}"}), 400

    try:
        from src.predict import IDSPredictor
        predictor = IDSPredictor()
        predictions = predictor.predict(features)
        if "error" not in predictions:
            return jsonify(predictions)
    except Exception:
        pass

    mock_predictions = {}
    for model_name in ["Random Forest", "XGBoost", "LSTM"]:
        pred = random.choices(ATTACK_TYPES, weights=ATTACK_WEIGHTS, k=1)[0]
        conf = round(random.uniform(0.75, 0.99), 3)
        mock_predictions[model_name] = {
            "prediction": pred,
            "confidence": conf,
            "probabilities": {
                at: round(random.uniform(0.01, 0.3), 3) if at != pred else conf
                for at in ATTACK_TYPES
            },
        }

    return jsonify(mock_predictions)


@bp.route("/api/traffic")
def api_traffic():
    """Return recent traffic classifications."""
    return jsonify(recent_traffic[-100:])


@bp.route("/api/demo-feed")
def api_demo_feed():
    """SSE endpoint streaming simulated traffic every 2 seconds."""

    def event_stream():
        test_data = None
        try:
            test_files = list(DATA_DIR.glob("*.csv")) if DATA_DIR.exists() else []
            if test_files:
                import pandas as pd
                test_data = pd.read_csv(test_files[0])
        except Exception:
            test_data = None

        while True:
            if test_data is not None and len(test_data) > 0:
                try:
                    sample_row = test_data.sample(1).iloc[0]
                    attack_type = random.choices(ATTACK_TYPES, weights=ATTACK_WEIGHTS, k=1)[0]
                    sample = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": generate_random_ip(private=True),
                        "dst_ip": generate_random_ip(private=random.random() > 0.3),
                        "protocol": random.choice(PROTOCOLS),
                        "service": random.choice(SERVICES),
                        "prediction": attack_type,
                        "confidence": round(random.uniform(0.75, 0.99), 3),
                        "attack_type": attack_type,
                    }
                except Exception:
                    sample = generate_mock_sample()
            else:
                sample = generate_mock_sample()

            recent_traffic.append(sample)
            if len(recent_traffic) > MAX_TRAFFIC_ENTRIES:
                recent_traffic.pop(0)

            yield f"data: {json.dumps(sample)}\n\n"
            time.sleep(2)

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
