"""
Trains a baseline Naive Bayes phishing/spam classifier on a small bundled
sample dataset (sample_dataset.csv). This is intentionally a lightweight
starting point per the build spec ("start with Naive Bayes/SVM on a public
phishing dataset; can upgrade to a transformer model later").

To upgrade: replace sample_dataset.csv with a larger public corpus
(e.g. Enron, SpamAssassin, Nazario phishing corpus, PhishTank exports)
mapped to the same two columns: text,label (label = 1 phishing/spam, 0 legit).

Run:  python train_model.py
Outputs: phishing_model.joblib, vectorizer.joblib (in this directory)
"""
import os
import csv
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(HERE, 'sample_dataset.csv')
MODEL_PATH = os.path.join(HERE, 'phishing_model.joblib')


def load_dataset():
    texts, labels = [], []
    with open(DATASET_PATH, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            texts.append(row['text'])
            labels.append(int(row['label']))
    return texts, labels


def main():
    texts, labels = load_dataset()
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(stop_words='english', ngram_range=(1, 2), min_df=1)),
        ('clf', MultinomialNB()),
    ])
    pipeline.fit(texts, labels)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model trained on {len(texts)} samples and saved to {MODEL_PATH}")


if __name__ == '__main__':
    main()
