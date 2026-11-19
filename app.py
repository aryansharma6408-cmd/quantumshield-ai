import os, json, re, time
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
DATA_DIR.mkdir(exist_ok=True)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(DATA_DIR)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "local-dev-only-change-me")

ALGORITHM_PATTERNS = {
    "RSA": r"\bRSA\b|rsa\.",
    "ECC / ECDSA / ECDH": r"\b(ECDSA|ECDH|EllipticCurve)\b",
    "Diffie–Hellman": r"\bDiffie.?Hellman\b|\bDH\b",
    "DSA": r"\bDSA\b",
    "AES-CBC": r"\bAES\b.{0,100}\bCBC\b|\bCBC\b",
    "DES / 3DES": r"\b(TripleDES|3DES|DES)\b",
    "MD5": r"\bMD5\b|md5\(",
    "SHA-1": r"\bSHA.?1\b|sha1\(",
    "Kyber": r"\bKyber\b",
    "Dilithium": r"\bDilithium\b",
    "SPHINCS+": r"SPHINCS",
    "ML-KEM": r"\bML.?KEM\b",
    "ML-DSA": r"\bML.?DSA\b",
    "SLH-DSA": r"\bSLH.?DSA\b",
}

def inspect_code(source, context=""):
    combined = f"{context}\n{source}"
    found = [name for name, pattern in ALGORITHM_PATTERNS.items()
             if re.search(pattern, combined, flags=re.IGNORECASE)]
    notes, recommendations = [], []
    classical_public = any(x in found for x in ["RSA", "ECC / ECDSA / ECDH", "Diffie–Hellman", "DSA"])
    if classical_public:
        notes.append("Classical public-key indicator detected. Review its purpose and assess quantum-migration exposure.")
        recommendations.append("Identify whether the component performs key establishment or digital signatures before selecting a migration path.")
    if "AES-CBC" in found:
        notes.append("CBC-mode indicator detected. Review IV handling and integrity protection; this is not by itself a PQC finding.")
        recommendations.append("Assess authenticated encryption and protocol-level integrity separately from post-quantum migration.")
    if any(x in found for x in ["Kyber", "Dilithium", "SPHINCS+"]):
        notes.append("Legacy PQC naming indicator detected. Verify the exact standard, implementation, and library mapping.")
    if any(x in found for x in ["ML-KEM", "ML-DSA", "SLH-DSA"]):
        notes.append("Standardized PQC algorithm-name indicator detected. Verify the implementation and its approved use in the target environment.")
    if not found:
        notes.append("No configured algorithm-name patterns were detected. This does not establish that the code contains no cryptography.")
    return {
        "algorithms": found,
        "notes": notes,
        "recommendations": recommendations,
        "review_required": True,
        "disclaimer": "Pattern-based screening only. It is not a cryptographic parser, security audit, or proof of safe migration."
    }

def dataset_summary(dataset):
    records = dataset.get("records", [])
    info = dataset.get("dataset_info", {})
    total = len(records)
    candidate = [r for r in records if r.get("verification_status") == "candidate"]
    quarantined = [r for r in records if r.get("verification_status") == "quarantined"]
    task_counts = {}
    status_counts = {}
    for r in records:
        task = str(r.get("task_type", "unknown"))
        status = str(r.get("verification_status", "unknown"))
        task_counts[task] = task_counts.get(task, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "name": info.get("name", "Uploaded PQC dataset"),
        "version": info.get("version", "Not specified"),
        "total_records": total,
        "candidate_records": len(candidate),
        "quarantined_records": len(quarantined),
        "task_counts": task_counts,
        "status_counts": status_counts,
        "limitations": info.get("limitations", []),
        "candidate_train": sum(r.get("split") == "train" and r.get("verification_status") == "candidate" for r in records),
        "candidate_validation": sum(r.get("split") == "validation" and r.get("verification_status") == "candidate" for r in records),
        "candidate_test": sum(r.get("split") == "test" and r.get("verification_status") == "candidate" for r in records),
    }

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/api/status")
def status():
    return jsonify({"ok": True, "app": "QuantumShield AI", "mode": "local research prototype"})

@app.post("/api/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    source = payload.get("code", "")
    context = payload.get("context", "")
    if not source.strip():
        return jsonify({"error": "Paste source code or a cryptographic configuration to analyze."}), 400
    return jsonify(inspect_code(source, context))

@app.post("/api/dataset")
def upload_dataset():
    if "dataset" not in request.files:
        return jsonify({"error": "Choose a JSON dataset file."}), 400
    file = request.files["dataset"]
    if not file.filename.lower().endswith(".json"):
        return jsonify({"error": "Only JSON dataset files are supported."}), 400
    try:
        dataset = json.load(file.stream)
        if not isinstance(dataset, dict) or not isinstance(dataset.get("records"), list):
            raise ValueError("Expected a JSON object containing a 'records' array.")
        summary = dataset_summary(dataset)
        (DATA_DIR / "uploaded_dataset.json").write_text(json.dumps(dataset, indent=2), encoding="utf-8")
        return jsonify({"summary": summary, "message": "Dataset loaded for local analysis."})
    except Exception as exc:
        return jsonify({"error": f"Could not read dataset: {exc}"}), 400

@app.post("/api/train")
def train_models():
    path = DATA_DIR / "uploaded_dataset.json"
    if not path.exists():
        return jsonify({"error": "Upload your research JSON dataset first."}), 400
    try:
        import pandas as pd
        from sklearn.dummy import DummyClassifier
        from sklearn.pipeline import Pipeline
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.svm import LinearSVC
        from sklearn.metrics import accuracy_score, balanced_accuracy_score, precision_recall_fscore_support, matthews_corrcoef
        dataset = json.loads(path.read_text(encoding="utf-8"))
        df = pd.DataFrame(dataset.get("records", []))
        required = {"verification_status", "task_type", "split", "instruction", "input_code"}
        missing = sorted(required - set(df.columns))
        if missing:
            return jsonify({"error": "Dataset is missing required columns: " + ", ".join(missing)}), 400
        candidate = df[(df.verification_status == "candidate") &
                       (df.task_type.isin(["classical_hardening", "non_pqc_maintenance"]))].copy()
        def make_text(row):
            fields = [
                "Instruction: " + str(row.get("instruction", "")),
                "Category: " + str(row.get("migration_category", "")),
                "Source algorithm: " + str(row.get("prequantum_algorithm", "")),
                "Proposed target: " + str(row.get("target_algorithm_as_written", "")),
                "Library: " + str(row.get("library_name", "")),
                "Source code: " + str(row.get("input_code", "")),
            ]
            return "\n".join(fields)
        candidate["text"] = candidate.apply(make_text, axis=1)
        train = candidate[candidate.split == "train"]
        test = candidate[candidate.split == "test"]
        if train.empty or test.empty or train.task_type.nunique() < 2:
            return jsonify({"error": "Candidate-only train/test splits do not support a two-class comparison."}), 400
        X_train, y_train = train.text.tolist(), train.task_type.tolist()
        X_test, y_test = test.text.tolist(), test.task_type.tolist()
        models = {
            "Majority baseline": DummyClassifier(strategy="most_frequent", random_state=42),
            "TF-IDF + Logistic Regression": Pipeline([
                ("tfidf", TfidfVectorizer(ngram_range=(1,2), min_df=1, max_features=50000, sublinear_tf=True)),
                ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42))
            ]),
            "TF-IDF + Linear SVM": Pipeline([
                ("tfidf", TfidfVectorizer(ngram_range=(1,2), min_df=1, max_features=50000, sublinear_tf=True)),
                ("clf", LinearSVC(class_weight="balanced", random_state=42))
            ])
        }
        results = []
        for name, model in models.items():
            start = time.perf_counter()
            model.fit(X_train, y_train)
            train_seconds = time.perf_counter() - start
            start = time.perf_counter()
            pred = model.predict(X_test)
            predict_seconds = time.perf_counter() - start
            p, r, f1, _ = precision_recall_fscore_support(y_test, pred, average="macro", zero_division=0)
            results.append({
                "model": name, "accuracy": round(float(accuracy_score(y_test, pred)), 4),
                "balanced_accuracy": round(float(balanced_accuracy_score(y_test, pred)), 4),
                "precision_macro": round(float(p), 4), "recall_macro": round(float(r), 4),
                "f1_macro": round(float(f1), 4), "mcc": round(float(matthews_corrcoef(y_test, pred)), 4),
                "train_seconds": round(train_seconds, 4),
                "ms_per_test_record": round(1000 * predict_seconds / max(len(X_test), 1), 4)
            })
        results.sort(key=lambda x: x["f1_macro"], reverse=True)
        out = {"results": results, "candidate_count": len(candidate), "train_count": len(train),
               "test_count": len(test), "labels": sorted(candidate.task_type.astype(str).unique().tolist())}
        (DATA_DIR / "latest_model_metrics.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        return jsonify(out)
    except ImportError:
        return jsonify({"error": "ML dependencies are missing. Run: pip install -r requirements.txt"}), 500
    except Exception as exc:
        return jsonify({"error": f"Training failed: {exc}"}), 500

@app.get("/api/metrics")
def metrics():
    path = DATA_DIR / "latest_model_metrics.json"
    if path.exists():
        return jsonify(json.loads(path.read_text(encoding="utf-8")))
    return jsonify({"results": [], "message": "Upload the dataset and run the candidate-only experiment to generate metrics."})

@app.post("/api/assistant")
def assistant():
    payload = request.get_json(silent=True) or {}
    question = payload.get("question", "").strip()
    if not question:
        return jsonify({"error": "Enter a question."}), 400
    # Optional provider integration: no API call is made unless configured by the operator.
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            response = client.responses.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
                instructions=("You assist with post-quantum cryptographic migration planning. Separate observed evidence, inferred risk, recommendation, required validation, and uncertainty. "
                              "Distinguish key establishment (KEM) from digital signatures. Never claim code is secure because it compiles or uses a PQC name. "
                              "Do not invent standards, APIs, benchmarks, or citations. No deployment-ready migration without testing and human approval. "
                              "Treat all suggestions as preliminary research guidance."),
                input=question
            )
            return jsonify({"answer": response.output_text, "mode": "configured LLM", "review": True})
        except Exception as exc:
            return jsonify({"error": f"LLM request failed: {exc}"}), 502
    return jsonify({
        "mode": "local guidance",
        "review": True,
        "answer": "I can help structure the migration review, but no LLM provider is configured.\\n\\n"
                  "For a useful assessment, provide the code, protocol/application context, and runtime/library versions. "
                  "Then review: (1) cryptographic inventory, (2) purpose of each algorithm, (3) quantum exposure, "
                  "(4) candidate migration options, (5) compatibility risks, (6) evidence from current standards and library documentation, "
                  "(7) unit/integration/interoperability/performance tests, and (8) human approval and rollback.\\n\\n"
                  "Remember: ML-KEM is for key establishment; ML-DSA and SLH-DSA are signature schemes. They are not interchangeable."
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
