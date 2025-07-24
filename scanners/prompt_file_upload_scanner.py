import os
import re
import docx2txt
import pytesseract
from PIL import Image
import pdfplumber

# PII & Secrets Patterns
PII_PATTERNS = {
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    "Phone": r"\b(?:\+?\d{1,3})?[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
}

PROMPT_INJECTION_PATTERNS = [
    r"(ignore|disregard).*(previous|earlier).*instructions",
    r"(pretend|assume).*(you are not|you are now)",
    r"#system", r"#ignore", r"\bforget\b.*prompt"
]

JABRALINK_OBFUSCATION_PATTERNS = [
    r"[\u200B-\u200D\uFEFF]",                            # Zero-width
    r"[^\x00-\x7F]{4,}",                                 # Unicode obfuscation
    r"🅰️|🆘|🔠|🔞|🆔",                                      # Emoji payload
    r"(subvocal|inject|simulate|bash|curl|morse)",       # Covert control terms
]

# -------------- Scanners -------------------

def detect_prompt_injection(text):
    return any(re.search(p, text, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS)

def detect_obfuscation(text):
    return any(re.search(p, text, re.IGNORECASE) for p in JABRALINK_OBFUSCATION_PATTERNS)

def detect_pii_and_secrets(text):
    results = {}
    for label, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            results[label] = list(set(matches))
    return results

# -------------- Extractors ------------------

def scan_pdf(file_path):
    with pdfplumber.open(file_path) as pdf:
        return ''.join([page.extract_text() or '' for page in pdf.pages])

def scan_docx(file_path):
    return docx2txt.process(file_path)

def scan_image(file_path):
    image = Image.open(file_path)
    return pytesseract.image_to_string(image)

# -------------- File Scanner ----------------

def scan_file(file_path):
    ext = os.path.splitext(file_path)[-1].lower()
    if ext == ".pdf":
        text = scan_pdf(file_path)
    elif ext in [".docx", ".doc"]:
        text = scan_docx(file_path)
    elif ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff"]:
        text = scan_image(file_path)
    else:
        raise ValueError(f"Unsupported file type: {ext}")

    issues = {
        "prompt_injection": detect_prompt_injection(text),
        "jabralink_obfuscation": detect_obfuscation(text),
        "pii_and_secrets": detect_pii_and_secrets(text),
        "text_preview": text[:500]
    }

    return issues
