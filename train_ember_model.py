import os
import joblib
import ember
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# ==============================
# CONFIG
# ==============================
DATA_DIR = r"C:\ember2018"   # CHANGE THIS to your EMBER dataset folder
MODEL_OUTPUT = "ember_model.pkl"

# ==============================
# LOAD EMBER DATASET
# ==============================
print("[+] Loading EMBER dataset...")

X_train, y_train = ember.read_vectorized_features(DATA_DIR, subset="train")
X_test, y_test = ember.read_vectorized_features(DATA_DIR, subset="test")

print("[+] Original train shape:", X_train.shape)
print("[+] Original test shape:", X_test.shape)

# ==============================
# REMOVE UNLABELED DATA
# EMBER uses -1 for unlabeled samples
# ==============================
print("[+] Removing unlabeled samples...")

train_mask = y_train != -1
test_mask = y_test != -1

X_train = X_train[train_mask]
y_train = y_train[train_mask]

X_test = X_test[test_mask]
y_test = y_test[test_mask]

print("[+] Labeled train shape:", X_train.shape)
print("[+] Labeled test shape:", X_test.shape)

# ==============================
# TRAIN MODEL
# ==============================
print("[+] Training model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("[+] Training completed.")

# ==============================
# EVALUATE MODEL
# ==============================
print("[+] Evaluating model...")

y_pred = model.predict(X_test)

if hasattr(model, "predict_proba"):
    y_score = model.predict_proba(X_test)[:, 1]
else:
    y_score = y_pred

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_score)
cm = confusion_matrix(y_test, y_pred)

print("\n==============================")
print("MODEL EVALUATION RESULT")
print("==============================")
print("Accuracy :", accuracy)
print("Precision:", precision)
print("Recall   :", recall)
print("F1-score :", f1)
print("ROC-AUC  :", roc_auc)

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ==============================
# SAVE MODEL
# ==============================
print("[+] Saving model...")

joblib.dump(model, MODEL_OUTPUT)

print(f"[+] Model saved as: {MODEL_OUTPUT}")
print("[+] Put this file in the same folder as your SmartLock Stealth app.")