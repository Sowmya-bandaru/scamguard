"""Train the ScamGuard baseline model.   Run:  python train.py"""
import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

CUSTOM_WEIGHT = 5  # our India-specific messages count more than the generic dataset

frames = []

custom = pd.read_csv("custom_data.csv")
custom["weight"] = CUSTOM_WEIGHT
frames.append(custom[["text", "label", "weight"]])

if os.path.exists("spam.csv"):
    uci = pd.read_csv("spam.csv", encoding="latin-1")[["v1", "v2"]]
    uci.columns = ["label", "text"]
    uci["label"] = (uci["label"] == "spam").astype(int)
    uci["weight"] = 1
    frames.append(uci[["text", "label", "weight"]])
    print("Training on spam.csv + custom_data.csv")
else:
    print("spam.csv not found - training on custom_data.csv only")

df = pd.concat(frames, ignore_index=True).dropna()
df["text"] = df["text"].astype(str).str.lower()
df = df.drop_duplicates(subset="text")
print("Messages:", len(df), "| scams:", int(df["label"].sum()), "| safe:", int((df["label"] == 0).sum()))

X_train, X_test, y_train, y_test, w_train, _ = train_test_split(
    df["text"], df["label"], df["weight"],
    test_size=0.25, random_state=42, stratify=df["label"],
)

model = make_pipeline(
    TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True),
    LogisticRegression(class_weight="balanced", max_iter=2000),
)
model.fit(X_train, y_train, logisticregression__sample_weight=w_train)

print(classification_report(y_test, model.predict(X_test), target_names=["safe", "scam"], zero_division=0))

joblib.dump(model, "model.joblib")
print("Saved model.joblib")
