"""
train_model.py
---------------
Trains the AI CyberShield detection model:

  1. RandomForestClassifier  -> multi-class attack classification
                                 (normal / ddos / portscan / bruteforce /
                                  sqli / phishing / malware)
  2. IsolationForest         -> unsupervised anomaly scoring, used as a
                                 secondary signal for traffic the
                                 classifier has low confidence on (i.e.
                                 novel/zero-day-like behaviour)

Artifacts are written to model/artifacts/:
  - classifier.joblib
  - anomaly_detector.joblib
  - encoders.joblib   (LabelEncoders for categorical columns + target)
  - feature_columns.json
  - metrics.json
"""

import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

DATA_PATH = "data/traffic_dataset.csv"
ARTIFACT_DIR = "model/artifacts"
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
TARGET_COL = "label"


def main():
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    df = pd.read_csv(DATA_PATH)

    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le

    target_le = LabelEncoder()
    df["label_enc"] = target_le.fit_transform(df[TARGET_COL])
    encoders["__target__"] = target_le

    feature_cols = [c for c in df.columns if c not in (TARGET_COL, "label_enc")]
    X = df[feature_cols]
    y = df["label_enc"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=14,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(
        y_test, y_pred, target_names=target_le.classes_, output_dict=True
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Anomaly detector trained only on "normal" traffic so it flags
    # anything that deviates from the learned baseline.
    normal_mask = df[TARGET_COL] == "normal"
    iso = IsolationForest(
        n_estimators=150, contamination=0.05, random_state=42, n_jobs=-1
    )
    iso.fit(df.loc[normal_mask, feature_cols])

    joblib.dump(clf, f"{ARTIFACT_DIR}/classifier.joblib")
    joblib.dump(iso, f"{ARTIFACT_DIR}/anomaly_detector.joblib")
    joblib.dump(encoders, f"{ARTIFACT_DIR}/encoders.joblib")
    with open(f"{ARTIFACT_DIR}/feature_columns.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    importances = sorted(
        zip(feature_cols, clf.feature_importances_), key=lambda x: -x[1]
    )
    metrics = {
        "accuracy": report["accuracy"],
        "macro_f1": report["macro avg"]["f1-score"],
        "per_class": {
            k: v for k, v in report.items() if k in target_le.classes_
        },
        "confusion_matrix": cm,
        "class_order": target_le.classes_.tolist(),
        "top_features": [{"feature": f, "importance": round(float(i), 4)} for f, i in importances[:10]],
    }
    with open(f"{ARTIFACT_DIR}/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"Accuracy: {metrics['accuracy']:.4f}   Macro F1: {metrics['macro_f1']:.4f}")
    print("\nTop features:")
    for item in metrics["top_features"]:
        print(f"  {item['feature']:<28} {item['importance']}")
    print(f"\nArtifacts saved to {ARTIFACT_DIR}/")


if __name__ == "__main__":
    main()
