"""
USP 7: Self-improving model — analyst verdicts (Confirmed Phishing /
False Positive) are fed back into the training set, and the classifier
is retrained so future false positives on similar content decrease over time.
"""
import os
import csv
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(HERE, '..', 'ml_model')
BASE_DATASET = os.path.join(ML_DIR, 'sample_dataset.csv')
FEEDBACK_DATASET = os.path.join(ML_DIR, 'feedback_dataset.csv')
MODEL_PATH = os.path.join(ML_DIR, 'phishing_model.joblib')

if not os.path.exists(FEEDBACK_DATASET):
    with open(FEEDBACK_DATASET, 'w', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow(['text', 'label'])


def add_feedback_example(text, label):
    """label: 1 = confirmed phishing, 0 = confirmed false positive (legitimate)"""
    if not text or not text.strip():
        return False
    with open(FEEDBACK_DATASET, 'a', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow([text.strip().replace('\n', ' ')[:5000], label])
    return True


def _load_csv(path):
    texts, labels = [], []
    if not os.path.exists(path):
        return texts, labels
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row.get('text'):
                texts.append(row['text'])
                labels.append(int(row['label']))
    return texts, labels


def retrain_with_feedback():
    """Merges the original bundled dataset with all analyst feedback
    collected so far, and retrains the Naive Bayes classifier in place."""
    base_texts, base_labels = _load_csv(BASE_DATASET)
    fb_texts, fb_labels = _load_csv(FEEDBACK_DATASET)

    all_texts = base_texts + fb_texts
    all_labels = base_labels + fb_labels

    if len(set(all_labels)) < 2:
        return {'status': 'error', 'message': 'Need both phishing and legitimate examples to retrain.'}

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(stop_words='english', ngram_range=(1, 2), min_df=1)),
        ('clf', MultinomialNB()),
    ])
    pipeline.fit(all_texts, all_labels)
    joblib.dump(pipeline, MODEL_PATH)

    return {
        'status': 'success',
        'total_samples': len(all_texts),
        'base_samples': len(base_texts),
        'feedback_samples': len(fb_texts),
    }
