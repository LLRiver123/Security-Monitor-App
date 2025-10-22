import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
import joblib
import argparse

# usage: python train_lof.py --input events_normal.csv --out model.joblib
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", default="agent/ai/lof_model.joblib")
    parser.add_argument("--n_neighbors", type=int, default=20)
    parser.add_argument("--contamination", type=float, default=0.01)
    args = parser.parse_args()

    df = pd.read_csv(args.input)  # assumes precomputed numeric feature columns
    feature_cols = [c for c in df.columns if c not in ("id","label","timestamp")]
    X = df[feature_cols].fillna(0).values

    scaler = StandardScaler()
    lof = LocalOutlierFactor(n_neighbors=args.n_neighbors, contamination=args.contamination, novelty=True, n_jobs=-1)

    # pipeline: scale -> lof
    pipeline = Pipeline([("scaler", scaler), ("lof", lof)])
    pipeline.fit(X)  # fits scaler and fits LOF as "normal model"

    joblib.dump({"pipeline": pipeline, "features": feature_cols}, args.out)
    print("Saved model to", args.out)