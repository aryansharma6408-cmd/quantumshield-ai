# QuantumShield AI — Post-Quantum Migration Research Dashboard

A local full-stack research/exhibition prototype based on the uploaded Google Colab notebook, **LLM-Assisted Cryptographic Migration for Post-Quantum Agility**.

## Features
- Futuristic cybersecurity dashboard UI.
- Pattern-based code screening using the algorithm indicators from the notebook.
- Upload and audit a JSON dataset containing a `records` array.
- Candidate-only experiment: Majority baseline, TF-IDF + Logistic Regression, and TF-IDF + Linear SVM.
- Reports accuracy, balanced accuracy, macro precision/recall/F1, MCC, training time, and per-record inference latency.
- Optional LLM assistant via an environment variable.
- Explicit research limitations and human-review warnings.

## Run locally
Requires Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Load your research dataset
Use the **Dataset Lab** page and upload your final JSON dataset (the notebook expects a JSON object with `dataset_info` and `records`).

The training endpoint intentionally uses only records where `verification_status == "candidate"` and `task_type` is `classical_hardening` or `non_pqc_maintenance`. Quarantined records are never used as target labels. The model comparison is task-type classification, not proof of cryptographic correctness.

## Optional LLM integration
Set an API key in your local environment before starting the app:

```bash
# Windows PowerShell
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_MODEL="gpt-4.1-mini"
python app.py

# macOS/Linux
export OPENAI_API_KEY="your-key"
export OPENAI_MODEL="gpt-4.1-mini"
python app.py
```

Do not put API keys in frontend files or commit them to a public repository. Without a key, the assistant returns safe local guidance and does not make an external model call.

## Important research integrity notes
- Dataset metadata in the supplied notebook says no record is verified; quarantined records are excluded from supervised training.
- The supplied experiment is limited to two candidate task types and does not measure true PQC migration correctness.
- Pattern matching is only a screening aid, not a cryptographic parser or security audit.
- No generated migration code is labeled secure unless independently reviewed and tested.
- DistilBERT is not silently reported as a result. This starter app leaves the optional transformer experiment out of the web UI until it is run and its actual output is imported.
- The app does not deploy or automatically modify cryptographic code.


## Public deployment (Render)
1. Create a GitHub repository and upload the contents of this folder (not the ZIP itself).
2. In Render, choose **New → Web Service**, connect the repository, and deploy.
3. The included `render.yaml` configures the Python build and Gunicorn start command. If entering settings manually, use:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app:app --bind 0.0.0.0:$PORT`
4. Keep `OPENAI_API_KEY` out of GitHub and add it only as a private environment variable in Render if you choose to enable the optional LLM.

## Public demo cautions
This is an exhibition prototype, not a production security service. Do not upload confidential source code, private keys, credentials, or sensitive datasets. The demo does not include user accounts or access controls. Uploaded datasets are stored on the server's local filesystem, which may be temporary on a free host and should not be treated as permanent storage. Anyone with the public link can use the app, so consider leaving the LLM key unset for an open exhibition demo.
