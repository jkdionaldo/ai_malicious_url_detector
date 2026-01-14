Put your malicious URL CSV file in this folder.

Example:

- data/malicious_url.csv

Common Kaggle column patterns:

- url + type
- url + label

Run (no --csv required):
python src/malicious_url_detection.py

Optional (print classification report during training):
python src/malicious_url_detection.py --evaluate

If your dataset has unusual column names, point to it directly:
python src/malicious_url_detection.py --csv data/malicious_url.csv
