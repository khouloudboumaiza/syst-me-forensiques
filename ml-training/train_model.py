"""
train_model.py
---------------
Entraîne un modèle de détection d'intrusion réseau (Random Forest) à partir
des datasets CICIDS2017 et/ou UNSW-NB15.

Usage :
    python train_model.py --data-dir "C:\dfir\datasets" --out-dir "C:\dfir\model"

Le dossier --data-dir doit contenir directement les fichiers .csv des datasets
(mettez tous les CSV de CICIDS et/ou UNSW-NB15 dans le même dossier, peu importe
le nom exact, le script les fusionne).
"""

import argparse
import glob
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score


def load_and_clean(data_dir: str) -> pd.DataFrame:
    files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not files:
        raise FileNotFoundError(f"Aucun .csv trouvé dans {data_dir}")

    frames = []
    for f in files:
        try:
            df = pd.read_csv(f, encoding="latin1", low_memory=False)
            df.columns = df.columns.str.strip()
            frames.append(df)
            print(f"Chargé : {os.path.basename(f)} ({len(df)} lignes)")
        except Exception as e:
            print(f"Ignoré {f} : {e}")

    full = pd.concat(frames, ignore_index=True, sort=False)

    # Trouver la colonne label (nom variable selon dataset : Label, label, attack_cat...)
    label_col = None
    for candidate in ["Label", "label", "attack_cat", "Attack"]:
        if candidate in full.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError("Colonne label introuvable dans les CSV.")

    # Normaliser en binaire BENIGN / ATTACK
    def normalize_label(v):
        v = str(v).strip().upper()
        if v in ("BENIGN", "NORMAL", "0"):
            return "BENIGN"
        return "ATTACK"

    full["Label"] = full[label_col].apply(normalize_label)

    # Garder uniquement les colonnes numériques + label
    numeric_cols = full.select_dtypes(include="number").columns.tolist()
    full = full[numeric_cols + ["Label"]]

    full = full.replace([float("inf"), float("-inf")], pd.NA)
    full = full.dropna()

    print(f"\nTotal après nettoyage : {len(full)} lignes, {len(numeric_cols)} features")
    print(full["Label"].value_counts())

    return full


def train(df: pd.DataFrame, out_dir: str):
    X = df.drop(columns=["Label"])
    y = LabelEncoder().fit_transform(df["Label"])  # BENIGN=0, ATTACK=1 (ordre alphabétique)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=150, max_depth=20, n_jobs=-1, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print("\n=== Résultats sur jeu de test ===")
    print("Accuracy :", accuracy_score(y_test, preds))
    print(classification_report(y_test, preds, target_names=["BENIGN", "ATTACK"]))

    os.makedirs(out_dir, exist_ok=True)
    joblib.dump(model, os.path.join(out_dir, "network_ids_model.pkl"))
    joblib.dump(list(X.columns), os.path.join(out_dir, "model_features.pkl"))
    print(f"\nModèle sauvegardé dans : {out_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True, help="Dossier contenant les CSV d'entraînement")
    parser.add_argument("--out-dir", default="./model", help="Dossier de sortie pour le modèle")
    args = parser.parse_args()

    data = load_and_clean(args.data_dir)
    train(data, args.out_dir)