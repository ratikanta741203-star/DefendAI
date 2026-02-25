import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pickle

# Load dataset
data = pd.read_csv("dataset.csv")

X = data["text"]
y = data["label"]

# Vectorization
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

# Model
model = LogisticRegression()
model.fit(X_vec, y)

# Save files
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model trained and saved successfully")