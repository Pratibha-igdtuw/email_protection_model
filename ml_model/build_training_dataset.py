"""
Builds training_dataset.csv from three public, real-world email corpora.
Re-run this any time to rebuild the exact dataset the shipped model was
trained on, or to pull fresh copies of the source corpora.

Sources (all public, commonly used in phishing-detection research):
  - Enron-Spam dataset      https://github.com/MWiechmann/enron_spam_data
                             (mirrored with subject/body/label columns at
                             https://github.com/rokibulroni/Phishing-Email-Dataset)
  - SpamAssassin public corpus (same mirror as above)
  - Nazario phishing corpus (Jose Nazario's hand-verified phishing corpus,
                             same mirror as above)

What this script does:
  1. Downloads the three source CSVs.
  2. Concatenates subject + body into a single `text` field per email.
  3. Strips newlines/whitespace, caps each email at 900 chars (classification
     signal is concentrated in the opening lines; this keeps the shipped
     dataset a manageable size without needing full email bodies).
  4. Stratified-samples Enron down to 8,000 emails (4,000 ham / 4,000 spam)
     so one very large source doesn't drown out the other two — SpamAssassin
     (~5,790) and Nazario (~1,550, phishing-only) are kept in full.
  5. Deduplicates identical text, shuffles, writes text,label to
     training_dataset.csv.

Run:  python build_training_dataset.py
Then: python train_model.py
"""
import csv
import os
import re
import sys
import random
import urllib.request

csv.field_size_limit(sys.maxsize)

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PATH = os.path.join(HERE, 'training_dataset.csv')

SOURCES = {
    'enron': 'https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/Enron.csv',
    'spamassassin': 'https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/SpamAssasin.csv',
    'nazario': 'https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/Nazario.csv',
}

PER_EMAIL_CHAR_CAP = 900
ENRON_SAMPLE_PER_CLASS = 4000
RANDOM_SEED = 42


def _clean(text):
    if text is None:
        return ""
    text = str(text).replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
    return re.sub(r'\s+', ' ', text).strip()


def _download(name, url):
    dest = os.path.join(HERE, f'_raw_{name}.csv')
    if not os.path.exists(dest):
        print(f"Downloading {name} from {url} ...")
        urllib.request.urlretrieve(url, dest)
    return dest


def _load(path):
    rows = []
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        for row in csv.DictReader(f):
            subj = _clean(row.get('subject', ''))
            body = _clean(row.get('body', ''))
            text = f"{subj} {body}".strip()[:PER_EMAIL_CHAR_CAP]
            label = row.get('label')
            if not text or len(text) < 15 or label not in ('0', '1'):
                continue
            rows.append((text, label))
    return rows


def main():
    random.seed(RANDOM_SEED)

    enron = _load(_download('enron', SOURCES['enron']))
    spamassassin = _load(_download('spamassassin', SOURCES['spamassassin']))
    nazario = _load(_download('nazario', SOURCES['nazario']))

    enron_0 = [r for r in enron if r[1] == '0']
    enron_1 = [r for r in enron if r[1] == '1']
    random.shuffle(enron_0)
    random.shuffle(enron_1)
    enron_sampled = enron_0[:ENRON_SAMPLE_PER_CLASS] + enron_1[:ENRON_SAMPLE_PER_CLASS]

    combined = nazario + spamassassin + enron_sampled
    random.shuffle(combined)

    seen = set()
    deduped = []
    for text, label in combined:
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append((text, label))

    with open(OUTPUT_PATH, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['text', 'label'])
        w.writerows(deduped)

    n_phish = sum(1 for _, l in deduped if l == '1')
    print(f"Wrote {len(deduped)} emails to {OUTPUT_PATH} "
          f"({n_phish} phishing/spam, {len(deduped) - n_phish} legitimate)")
    print("Sources: Enron (sampled), SpamAssassin (full), Nazario (full)")


if __name__ == '__main__':
    main()
