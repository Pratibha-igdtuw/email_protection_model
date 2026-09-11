"""
Trains the phishing/spam content classifier on real-world email corpora —
not synthetic/hand-written examples.

training_dataset.csv is a cleaned, deduplicated combination of three public,
widely-cited email corpora:

  - Enron corpus (ham + spam)      ~8,000 stratified sample  (source: Enron-Spam
                                     dataset, Metsis/Androutsopoulos/Paliouras 2006)
  - SpamAssassin public corpus     ~5,790 emails (ham + spam)
  - Nazario phishing corpus        ~1,550 verified real-world phishing emails
                                     (Jose Nazario's hand-verified phishing corpus)

Build script: see build_training_dataset.py in this directory for exactly how
training_dataset.csv was constructed (download, dedupe, stratified sampling,
per-email text cap) — re-run it any time to rebuild from the original sources.

label = 1 -> phishing/spam, label = 0 -> legitimate

To swap in a larger/updated corpus, replace training_dataset.csv with any
CSV that has the same two columns (text,label) and re-run this script.

Run:  python train_model.py
Outputs: phishing_model.joblib (in this directory)
"""
import os
import csv
import sys
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

csv.field_size_limit(sys.maxsize)

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(HERE, 'training_dataset.csv')
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
        ('tfidf', TfidfVectorizer(stop_words='english', ngram_range=(1, 2), min_df=2, max_df=0.9)),
        ('clf', MultinomialNB()),
    ])
    pipeline.fit(texts, labels)
    joblib.dump(pipeline, MODEL_PATH)
    n_phish = sum(labels)
    print(f"Model trained on {len(texts)} real emails "
          f"({n_phish} phishing/spam, {len(texts) - n_phish} legitimate) "
          f"and saved to {MODEL_PATH}")


if __name__ == '__main__':
    main()
