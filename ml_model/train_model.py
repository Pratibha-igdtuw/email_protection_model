import os
import csv
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

csv.field_size_limit(10 * 1024 * 1024)

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

    print(f"Total emails: {len(texts)}")

    # 80% training, 20% testing
    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.20,
        random_state=42,
        stratify=labels
    )

    print(f"Training emails: {len(X_train)}")
    print(f"Testing emails: {len(X_test)}")

    # Build ML pipeline
    pipeline = Pipeline([
        (
            'tfidf',
            TfidfVectorizer(
                stop_words='english',
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.9
            )
        ),
        (
            'clf',
            MultinomialNB()
        )
    ])

    # Train on training data only
    print("\nTraining model...")
    pipeline.fit(X_train, y_train)

    # Test on unseen data
    print("Testing model...\n")
    predictions = pipeline.predict(X_test)

    # Metrics
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)

    print("=" * 50)
    print("MODEL PERFORMANCE")
    print("=" * 50)

    print(f"Accuracy : {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision * 100:.2f}%)")
    print(f"Recall   : {recall:.4f} ({recall * 100:.2f}%)")
    print(f"F1 Score : {f1:.4f} ({f1 * 100:.2f}%)")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    print("\nDetailed Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=['Legitimate', 'Phishing/Spam']
        )
    )

    # Finally train the deployment model on ALL available data
    print("Training final model on all 15,283 emails...")
    pipeline.fit(texts, labels)

    joblib.dump(pipeline, MODEL_PATH)

    print("\n" + "=" * 50)
    print("FINAL MODEL SAVED")
    print("=" * 50)
    print(f"Model: {MODEL_PATH}")
    print(f"Total training emails: {len(texts)}")


if __name__ == '__main__':
    main()