import pandas as pd
import joblib
import numpy as np

model_data = joblib.load('agent/ai/lof_model.joblib')
pipeline = model_data['pipeline']
features = model_data['features']

df = pd.read_csv('data/features.csv')
X = df.fillna(0).values

# decision_function: larger -> more normal (depends on scikit-learn LOF), for novelty=True lower = more outlier
lof = pipeline.named_steps['lof']
scaler = pipeline.named_steps['scaler']
Xs = scaler.transform(X)
scores = lof.decision_function(Xs)  # higher = more normal; lower = more outlier

# convert to 0..100 suspicious score (simple mapping)
# negative scores more outlier-like: invert and scale
susp = (-scores)  # larger = more suspicious
# normalize to 0..1 by percentile or max
susp_norm = (susp - np.min(susp)) / (np.ptp(susp) + 1e-9)
susp_100 = (susp_norm * 100).astype(int)

df_out = pd.DataFrame({'score_raw': scores, 'suspicious': susp_100})
print(df_out.sort_values('score_raw').head(20))