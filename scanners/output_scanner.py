import re
from typing import Dict
import unicodedata

PII_PATTERNS = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Phone": r"\b(?:\+?\d{1,3})?[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Name": r"\b[A-Z][a-z]+ [A-Z][a-z]+\b",
    "IP Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
}

SECRETS_PATTERNS = {
    "API Key": r"(?i)(api|access|secret|token)[\s:=]+[a-z0-9\-_=]{16,}",
    "Basic Auth": r"Authorization:\s*Basic\s+[a-zA-Z0-9+/=]{16,}",
    "JWT": r"eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9._-]+?\.[a-zA-Z0-9._-]+",
    "Password": r"(?i)(password|pwd)[\s:=]+[^\s'\"\\]{6,}",
    "Mongo URI": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^ \n]+",
    "S3 URI": r"s3://[a-zA-Z0-9\-_./]+",
    "Base64": r"[A-Za-z0-9+/]{40,}={0,2}"
}

TOXICITY_WORDS = [
    "hate", "kill", "bomb", "terrorist", "nazi", "racist", "rape", "genocide", "slur"
]

def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text.lower())

def scan_output(text: str) -> Dict:
    report = {
        "pii": [],
        "secrets": [],
        "toxicity": [],
        "score": 0.0,
        "alerts": []
    }

    norm = normalize(text)

    for label, pattern in PII_PATTERNS.items():
        if re.search(pattern, norm):
            report["pii"].append(label)
            report["alerts"].append(f"🔐 PII Detected: {label}")

    for label, pattern in SECRETS_PATTERNS.items():
        if re.search(pattern, norm):
            report["secrets"].append(label)
            report["alerts"].append(f"🕵️ Secret Detected: {label}")

    for word in TOXICITY_WORDS:
        if word in norm:
            report["toxicity"].append(word)
            report["alerts"].append(f"☣️ Toxic word: {word}")

    score = 0.0
    score += 0.3 * len(report["pii"])
    score += 0.3 * len(report["secrets"])
    score += 0.4 if report["toxicity"] else 0.0
    report["score"] = min(score, 1.0)

    if not report["alerts"]:
        report["alerts"].append("✅ Output passed all scans.")

    return report
