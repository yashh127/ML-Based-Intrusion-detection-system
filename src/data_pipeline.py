"""
Data Pipeline for NSL-KDD Dataset.

Handles loading raw CSV files, encoding categorical features,
mapping attack labels to 5-class categories, scaling numeric features,
and saving processed data for model training.
"""

import logging
import pickle
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"

# ---------- NSL-KDD Column Names (41 features + label + difficulty) ----------
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label", "difficulty_level",
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

# ---------- Attack Label Mapping ----------
# Maps individual attack names to one of 5 categories
ATTACK_MAP = {
    "normal": "Normal",
    # DoS attacks
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS",
    "udpstorm": "DoS", "processtable": "DoS", "worm": "DoS",
    "mailbomb": "DoS",
    # Probe attacks
    "satan": "Probe", "ipsweep": "Probe", "nmap": "Probe",
    "portsweep": "Probe", "mscan": "Probe", "saint": "Probe",
    # R2L attacks
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L",
    "phf": "R2L", "multihop": "R2L", "warezclient": "R2L",
    "warezmaster": "R2L", "xlock": "R2L", "xsnoop": "R2L",
    "snmpguess": "R2L", "snmpgetattack": "R2L", "httptunnel": "R2L",
    "sendmail": "R2L", "named": "R2L", "spy": "R2L",
    # U2R attacks
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "xterm": "U2R", "ps": "U2R", "sqlattack": "U2R",
}

ATTACK_CLASSES = ["Normal", "DoS", "Probe", "R2L", "U2R"]
CLASS_TO_INT = {cls: i for i, cls in enumerate(ATTACK_CLASSES)}


def load_raw_data() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load raw NSL-KDD train and test CSV files.

    Returns:
        Tuple of (train_df, test_df).
    """
    train_path = RAW_DATA_DIR / "KDDTrain+.csv"
    test_path = RAW_DATA_DIR / "KDDTest+.csv"

    if not train_path.exists():
        # Try .txt extension
        train_path = RAW_DATA_DIR / "KDDTrain+.txt"
        test_path = RAW_DATA_DIR / "KDDTest+.txt"

    if not train_path.exists():
        raise FileNotFoundError(
            f"NSL-KDD data not found. Please place KDDTrain+.csv and "
            f"KDDTest+.csv in {RAW_DATA_DIR}"
        )

    logger.info("Loading training data from %s", train_path)
    train_df = pd.read_csv(train_path, names=COLUMN_NAMES, header=None)

    logger.info("Loading test data from %s", test_path)
    test_df = pd.read_csv(test_path, names=COLUMN_NAMES, header=None)

    logger.info(
        "Loaded %d training samples and %d test samples",
        len(train_df), len(test_df),
    )

    return train_df, test_df


def map_attack_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map raw attack labels to 5-class categories.

    Unknown attacks default to their closest category or 'Normal'.
    """
    df = df.copy()
    df["attack_category"] = df["label"].str.strip().str.lower().map(ATTACK_MAP)
    # Any unmapped labels → treat as attacks (likely novel attacks in test set)
    unmapped = df["attack_category"].isna()
    if unmapped.any():
        unmapped_labels = df.loc[unmapped, "label"].unique()
        logger.warning("Unmapped labels found: %s — mapping to nearest category", unmapped_labels)
        # Default unmapped to their closest match or 'DoS' (most common attack)
        df.loc[unmapped, "attack_category"] = "DoS"

    df["label_numeric"] = df["attack_category"].map(CLASS_TO_INT)
    return df


def preprocess_data(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, list, StandardScaler, OneHotEncoder]:
    """Preprocess NSL-KDD data: encode, scale, and transform features.

    Returns:
        X_train, X_test, y_train, y_test, feature_names, scaler, encoder
    """
    # Map labels
    train_df = map_attack_labels(train_df)
    test_df = map_attack_labels(test_df)

    y_train = train_df["label_numeric"].values
    y_test = test_df["label_numeric"].values

    # Drop non-feature columns
    drop_cols = ["label", "difficulty_level", "attack_category", "label_numeric"]
    X_train_raw = train_df.drop(columns=drop_cols)
    X_test_raw = test_df.drop(columns=drop_cols)

    # Separate numeric and categorical
    numeric_cols = [c for c in X_train_raw.columns if c not in CATEGORICAL_FEATURES]
    cat_cols = CATEGORICAL_FEATURES

    # One-hot encode categorical features
    encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
    cat_train = encoder.fit_transform(X_train_raw[cat_cols])
    cat_test = encoder.transform(X_test_raw[cat_cols])

    cat_feature_names = encoder.get_feature_names_out(cat_cols).tolist()

    # Scale numeric features
    scaler = StandardScaler()
    num_train = scaler.fit_transform(X_train_raw[numeric_cols].values.astype(np.float64))
    num_test = scaler.transform(X_test_raw[numeric_cols].values.astype(np.float64))

    # Combine
    X_train = np.hstack([num_train, cat_train])
    X_test = np.hstack([num_test, cat_test])
    feature_names = numeric_cols + cat_feature_names

    logger.info(
        "Preprocessing complete: %d features (numeric=%d, categorical=%d)",
        len(feature_names), len(numeric_cols), len(cat_feature_names),
    )

    return X_train, X_test, y_train, y_test, feature_names, scaler, encoder


def save_processed_data(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_names: list,
    scaler: StandardScaler,
    encoder: OneHotEncoder,
) -> None:
    """Save processed data and transformers to disk."""
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "feature_names": feature_names,
    }
    with open(PROCESSED_DATA_DIR / "processed_data.pkl", "wb") as f:
        pickle.dump(data, f)

    with open(PROCESSED_DATA_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    with open(PROCESSED_DATA_DIR / "encoder.pkl", "wb") as f:
        pickle.dump(encoder, f)

    logger.info("Saved processed data to %s", PROCESSED_DATA_DIR)


def load_processed_data() -> dict:
    """Load previously processed data from disk."""
    pkl_path = PROCESSED_DATA_DIR / "processed_data.pkl"
    if not pkl_path.exists():
        raise FileNotFoundError(f"Processed data not found at {pkl_path}. Run preprocessing first.")

    with open(pkl_path, "rb") as f:
        data = pickle.load(f)

    logger.info(
        "Loaded processed data: X_train=%s, X_test=%s",
        data["X_train"].shape, data["X_test"].shape,
    )
    return data


def get_train_test_data() -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, list]:
    """Load or create processed train/test data.

    Returns:
        X_train, X_test, y_train, y_test, feature_names
    """
    try:
        data = load_processed_data()
        return (
            data["X_train"], data["X_test"],
            data["y_train"], data["y_test"],
            data["feature_names"],
        )
    except FileNotFoundError:
        logger.info("Processed data not found. Running preprocessing pipeline...")
        train_df, test_df = load_raw_data()
        X_train, X_test, y_train, y_test, feature_names, scaler, encoder = preprocess_data(train_df, test_df)
        save_processed_data(X_train, X_test, y_train, y_test, feature_names, scaler, encoder)
        return X_train, X_test, y_train, y_test, feature_names


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    X_train, X_test, y_train, y_test, features = get_train_test_data()
    print(f"Training set: {X_train.shape}, Test set: {X_test.shape}")
    print(f"Classes distribution (train): {np.bincount(y_train)}")
    print(f"Features: {len(features)}")
