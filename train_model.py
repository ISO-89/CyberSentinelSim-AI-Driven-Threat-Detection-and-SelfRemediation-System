"""
train_model.py — ML Model Trainer
═══════════════════════════════════════════════════════════════
PURPOSE:
    Reads training data from data/train.csv and test data from
    data/test.csv. Trains two machine learning models — Naive Bayes
    and Random Forest — compares their accuracy and saves the better
    performing model to disk for analyzer.py to use.

MODELS TRAINED:
    1. Naive Bayes     — fast, lightweight, good with text data
    2. Random Forest   — slower, more powerful, handles complex patterns

THREAT CATEGORIES:
    0. Normal
    1. Brute Force
    2. SQL Injection
    3. Port Scan
    4. Malware Upload
    5. Privilege Escalation
    6. Unauthorized Access

INPUT:
    - data/train.csv  → training log lines with labels
    - data/test.csv   → test log lines with labels

OUTPUT:
    - models/log_classifier.pkl  → the saved best model
    - models/vectorizer.pkl      → the saved text vectorizer
    - models/label_map.pkl       → the saved label map
    - models/metadata.pkl        → accuracy and model stats
═══════════════════════════════════════════════════════════════
"""


import os
import pickle
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import cross_val_score


from config import LABEL_MAP, TRAIN_CSV, TEST_CSV, MODELS_DIR


def train_models():
    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── Load train and test CSV files ──────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  CYBER SENTINEL — Model Training Started")
    print(f"{'═'*60}\n")

    print("  Loading training data from data/train.csv...")
    train_df = pd.read_csv(TRAIN_CSV)
    print(f"  ✅ Training samples loaded : {len(train_df)}")

    print("  Loading test data from data/test.csv...")
    test_df = pd.read_csv(TEST_CSV)
    print(f"  ✅ Test samples loaded     : {len(test_df)}\n")

    # ── Split into features and labels ────────────────────────────────────────
    X_train = train_df["log_line"]
    y_train = train_df["label"]

    X_test  = test_df["log_line"]
    y_test  = test_df["label"]

    print(f"  {'Category':<25} {'Train':>8} {'Test':>8}")
    print(f"  {'-'*41}")
    for label_id, label_name in LABEL_MAP.items():
        train_count = len(train_df[train_df["label"] == label_id])
        test_count  = len(test_df[test_df["label"] == label_id])
        print(f"  {label_name:<25} {train_count:>8} {test_count:>8}")
    print(f"  {'-'*41}")
    print(f"  {'TOTAL':<25} {len(train_df):>8} {len(test_df):>8}\n")


    # ── TF-IDF Vectorizer (Sub-word Character N-Grams) ──────────────────────
    print("  Initializing TF-IDF Vectorizer...")

    # ACADEMIC NOTE: We use 'char_wb' (character n-grams within word boundaries)
    # instead of 'word' to prevent overfitting to exact template strings.
    # This forces the model to learn sub-word patterns (e.g., 'pass', 'sswo'),
    # making it resilient to typos, truncated logs, and formatting variations.
    
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",       # Character-level analysis within words
        ngram_range=(3, 5),       # Analyze chunks of 3, 4, and 5 characters
        max_features=5000,
        min_df=1,
        max_df=0.95,
        sublinear_tf=True,
        strip_accents="unicode"
        # Note: token_pattern is ignored when analyzer='char_wb'
    )

    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf  = vectorizer.transform(X_test)

    # Dynamically get the labels actually present in the test set (0, 2, 5)
    # This prevents crashes since we are no longer using all 7 classes
    present_labels = sorted(y_test.unique())
    present_names  = [LABEL_MAP[i] for i in present_labels]

    print(f"  ✅ Vocabulary size          : {len(vectorizer.vocabulary_)} unique sub-words")
    print(f"  ✅ Training feature matrix  : {X_train_tfidf.shape[0]} samples x {X_train_tfidf.shape[1]} features")
    print(f"  ✅ Testing feature matrix   : {X_test_tfidf.shape[0]} samples x {X_test_tfidf.shape[1]} features")
    print(f"  ✅ Active Classes           : {present_names}\n")


    # ── Train Naive Bayes Model ────────────────────────────────────────────────
    print("  Training Naive Bayes model...")

    nb_model = MultinomialNB(
        alpha=0.1,
        fit_prior=True,
        class_prior=None
    )

    nb_model.fit(X_train_tfidf, y_train)

    nb_predictions  = nb_model.predict(X_test_tfidf)
    nb_accuracy     = accuracy_score(y_test, nb_predictions)
    nb_cv_scores    = cross_val_score(nb_model, X_train_tfidf, y_train, cv=5)

    print(f"  ✅ Naive Bayes Accuracy     : {nb_accuracy * 100:.2f}%")
    print(f"  ✅ Naive Bayes CV Score     : {nb_cv_scores.mean() * 100:.2f}% (+/- {nb_cv_scores.std() * 100:.2f}%)\n")

    print("  Naive Bayes Classification Report:")
    print(classification_report(
        y_test,
        nb_predictions,
        labels=present_labels,         # <-- FIXED: Only use active labels
        target_names=present_names,    # <-- FIXED: Only use active names
        zero_division=0
    ))


    # ── Train Random Forest Model ──────────────────────────────────────────────
    print("  Training Random Forest model...")

    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        bootstrap=True,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
        criterion="gini",
        verbose=0
    )

    rf_model.fit(X_train_tfidf, y_train)

    rf_predictions  = rf_model.predict(X_test_tfidf)
    rf_accuracy     = accuracy_score(y_test, rf_predictions)
    rf_cv_scores    = cross_val_score(rf_model, X_train_tfidf, y_train, cv=5)

    print(f"  ✅ Random Forest Accuracy   : {rf_accuracy * 100:.2f}%")
    print(f"  ✅ Random Forest CV Score   : {rf_cv_scores.mean() * 100:.2f}% (+/- {rf_cv_scores.std() * 100:.2f}%)\n")

    print("  Random Forest Classification Report:")
    print(classification_report(
        y_test,
        rf_predictions,
        labels=present_labels,         # <-- FIXED: Only use active labels
        target_names=present_names,    # <-- FIXED: Only use active names
        zero_division=0
    ))


    # ── Model Comparison Table ─────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  MODEL COMPARISON TABLE")
    print(f"{'═'*60}")
    print(f"  {'Metric':<30} {'Naive Bayes':>12} {'Random Forest':>14}")
    print(f"  {'-'*56}")
    print(f"  {'Test Accuracy':<30} {nb_accuracy*100:>11.2f}% {rf_accuracy*100:>13.2f}%")
    print(f"  {'Cross Val Score (mean)':<30} {nb_cv_scores.mean()*100:>11.2f}% {rf_cv_scores.mean()*100:>13.2f}%")
    print(f"  {'Cross Val Score (std)':<30} {nb_cv_scores.std()*100:>11.2f}% {rf_cv_scores.std()*100:>13.2f}%")
    print(f"  {'Training Samples':<30} {len(X_train):>12} {len(X_train):>14}")
    print(f"  {'Testing Samples':<30} {len(X_test):>12} {len(X_test):>14}")
    print(f"  {'Vocabulary Size':<30} {len(vectorizer.vocabulary_):>12} {len(vectorizer.vocabulary_):>14}")
    print(f"  {'Number of Classes':<30} {len(present_labels):>12} {len(present_labels):>14}")
    print(f"{'═'*60}\n")

    # ── Pick the best model ────────────────────────────────────────────────────
    if rf_accuracy >= nb_accuracy:
        best_model      = rf_model
        best_model_name = "Random Forest"
        best_accuracy   = rf_accuracy
    else:
        best_model      = nb_model
        best_model_name = "Naive Bayes"
        best_accuracy   = nb_accuracy

    print(f"  ✅ Best Model  : {best_model_name}")
    print(f"  ✅ Accuracy    : {best_accuracy * 100:.2f}%\n")


    # ── Save everything to disk ────────────────────────────────────────────────
    print("  Saving models and vectorizer to disk...")

    # Save individual models for dual ensemble
    nb_path = os.path.join(MODELS_DIR, "nb_model.pkl")
    with open(nb_path, "wb") as f:
        pickle.dump(nb_model, f)

    rf_path = os.path.join(MODELS_DIR, "rf_model.pkl")
    with open(rf_path, "wb") as f:
        pickle.dump(rf_model, f)

    # Save the best model (backward compat)
    model_path = os.path.join(MODELS_DIR, "log_classifier.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(best_model, f)

    # Save the vectorizer
    vectorizer_path = os.path.join(MODELS_DIR, "vectorizer.pkl")
    with open(vectorizer_path, "wb") as f:
        pickle.dump(vectorizer, f)

    # Save the label map
    label_map_path = os.path.join(MODELS_DIR, "label_map.pkl")
    with open(label_map_path, "wb") as f:
        pickle.dump(LABEL_MAP, f)

    # Save model metadata for the dashboard to display
    metadata = {
        "best_model_name"  : best_model_name,
        "best_accuracy"    : best_accuracy,
        "nb_accuracy"      : nb_accuracy,
        "rf_accuracy"      : rf_accuracy,
        "nb_cv_mean"       : nb_cv_scores.mean(),
        "rf_cv_mean"       : rf_cv_scores.mean(),
        "nb_cv_std"        : nb_cv_scores.std(),
        "rf_cv_std"        : rf_cv_scores.std(),
        "total_train"      : len(train_df),
        "total_test"       : len(test_df),
        "vocabulary_size"  : len(vectorizer.vocabulary_),
        "num_classes"      : len(present_labels),
        "label_map"        : LABEL_MAP,
    }

    metadata_path = os.path.join(MODELS_DIR, "metadata.pkl")
    with open(metadata_path, "wb") as f:
        pickle.dump(metadata, f)

    print(f"  ✅ Naive Bayes    : {nb_path}")
    print(f"  ✅ Random Forest  : {rf_path}")
    print(f"  ✅ Best model     : {model_path}")
    print(f"  ✅ Vectorizer     : {vectorizer_path}")
    print(f"  ✅ Label map      : {label_map_path}")
    print(f"  ✅ Metadata       : {metadata_path}")
    print(f"\n{'═'*60}")
    print(f"  Training Complete!")
    print(f"{'═'*60}\n")

    return metadata


if __name__ == "__main__":
    train_models()




    