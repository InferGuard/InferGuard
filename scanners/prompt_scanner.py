import re
import unicodedata
from typing import List, Dict


# ✅ Patterns: Prompt Injection, Jailbreak, Social Engineering
PROMPT_INJECTION_PATTERNS = [
 
    r"(you are.*now.*free.*|no longer bound)",
    r"(you must respond as|simulate|impersonate)",
    r"(system prompt|#system|#ignore|#roleplay)",
    r"(jailbreak|do anything now|dan prompt|bypass)",
     # 🧠 Prompt Hijacking
    r"(ignore|disregard).*(previous|earlier).*instructions",
    r"(pretend|assume).*(you are not|you are now)",
    r"#system", r"#ignore", r"\bforget\b.*prompt",
    r"(you are an)? unrestricted (AI|assistant|bot)",
    r"(you now believe|you will always obey|your only task is)",
    r"(do not follow safety policies|disable moderation|no restrictions apply)",

    # 💣 Shell / Bash / Remote Code Exec
    r"curl\s+['\"]?https?:\/\/[^\"']+['\"]?\s*\|\s*(sh|bash|zsh|python)",
    r"wget\s+['\"]?https?:\/\/[^\"']+['\"]?\s*\|\s*(sh|bash|zsh|python)",
    r"(os\.system|subprocess\.Popen|eval|exec|Runtime\.getRuntime)\(",
    r"import\s+os\s*;.*system\(",
    r"rm\s+-rf\s+\/", r"sudo\s+.*", r"chmod\s+\+x", r"kill\s+-9",

    # 📦 Vector DB Poisoning / Prompt Data Injection
    r"<script>.*<\/script>",  # XSS-style payloads in embedded docs
    r"<img src=.* onerror=.*>",  # SVG/HTML-based injection
    r"(user|author):.*(ignore|override|inject)",  # fake metadata
    r"(system|assistant):.*",  # embedding fake roles
    r"\{.*\"role\":\s*\"system\".*\}",  # JSON system prompt poisoning

    # 🪪 Canary Tokens (trap file links or tracker URLs)
    r"https?:\/\/canarytokens\.com\/.*",
    r"https?:\/\/[a-z0-9\-]+\.ngrok\.io\/.*",
    r"https?:\/\/t\.co\/[a-zA-Z0-9]{5,}",
    r"(https?:\/\/[^\s]+\/token|secret|credential|auth)[^\s]+",

    # 🧬 LLM Behavior Manipulation
    r"(repeat after me|answer as|respond like|imitate the following style)",
    r"(you are free to make decisions|you are self-aware)",
    r"(begin a shell session|simulate a terminal|print a file list)",

    # 🕳 Payloads in disguised form
    r"(ignore|overrule)\s+.*?(this is not a test|instructions below)",
    r"base64\s+decode.*(echo|python|bash|eval)",
    r"this message contains admin override codes",
    r"::before\s*{.*content.*eval.*}",  # CSS-based injection
]

# ✅ Secrets and API Keys
PII_PATTERNS = {
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    "Phone": r"\b(?:\+?\d{1,3})?[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Name": r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b",
    "Address": r"\b\d{1,5}\s\w+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln)\b",
    "Date of Birth": r"\b\d{2}/\d{2}/\d{4}\b",
    "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Driver License": r"\b[A-Z]{1}\d{7}\b",
    "Passport Number": r"\b[A-Z]{2}[0-9]{6}\b",
    "National ID": r"\b\d{6,10}\b"
}

# ✅ Remote Execution Patterns
REMOTE_EXEC_PATTERNS = [
    r"curl\s+.*\|\s*bash",
    r"wget\s+.*\|\s*sh",
    r"(rm\s+-rf\s+/|shutdown\s+-h\s+now)",
    r"(python|node)\s+-c\s+['\"]import\s+[^\"]+['\"]"
]

# Simple regex-based PII patterns
SECRETS_PATTERNS = {
    # Personal Identifiable Information (PII)
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    "Phone": r"\b(?:\+?\d{1,3})?[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",

    # Credentials & Secrets
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|access)?.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key": r"\b[a-zA-Z0-9]{32,45}\b",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "Slack Token": r"xox[baprs]-[A-Za-z0-9-]{10,48}",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+",
    "OAuth Client Secret": r"(?i)(client_secret)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,64}[\"']?",
    "Password Assignment": r"(?i)(password|pwd)\s*[:=]\s*[\"']?.{6,64}[\"']?",
    "Private Key Block": r"-----BEGIN (EC |DSA |RSA |OPENSSH |)PRIVATE KEY-----",
    "Certificate PEM": r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
    "MongoDB URI": r"mongodb(\+srv)?:\/\/[^\/\s]+",
    "PostgreSQL URI": r"postgres:\/\/[^\s]+",
    "MySQL URI": r"mysql:\/\/[^\s]+",
    "Generic URI/Connection String": r"\b(?:jdbc|mysql|postgres|redis|mongodb|amqp):\/\/[^ ]+",

    # Cloud Provider Keys
    "SSH Private Key": r"-----BEGIN (OPENSSH|RSA|DSA|EC|ED25519) PRIVATE KEY-----",
    "GCP Service Account Key": r'"type": "service_account",\s*"project_id": "[^"]+",\s*"private_key_id": "[^"]+"',
    "Azure Storage Key": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net",
    "Tencent SecretId": r"TENCENT[A-Z0-9]{32}",
    "AliCloud Access Key": r"(?<![A-Za-z0-9])[A-Za-z0-9]{20}(?![A-Za-z0-9])",  # context required
    "AliCloud Secret Key": r"(?<![A-Za-z0-9])[A-Za-z0-9/+=]{30,50}(?![A-Za-z0-9])",  # context required

    # Databases & Middleware
    "Redis URI": r"redis://[^@]+@[^:]+:\d+",
    "Cassandra URI": r"cassandra:\/\/[^\s]+",
    "Elasticsearch Basic Auth": r"https?:\/\/[^:]+:[^@]+@[^\/]+",

    # Generic Database Credentials
    "Generic DB Password": r"(?i)(db_pass|database_password|sql_pass)\s*[:=]\s*[\"']?.{6,64}[\"']?",
    "Generic DB URI": r"(postgres|mysql|mongodb|mariadb|oracle):\/\/[^:]+:[^@]+@[^\/\s]+",

     # Cloud Storage URIs
    "Amazon S3 URI": r"s3:\/\/[a-z0-9\-_\.]+\/[^\s\"'>]+",
    "AWS S3 Signed URL": r"https:\/\/s3[-a-z0-9]*\.amazonaws\.com\/[^\s\"']+\?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=",
    "Google Cloud Storage URI": r"gs:\/\/[a-z0-9\-_\.]+\/[^\s\"'>]+",
    "Azure Blob Storage URL": r"https:\/\/[a-z0-9]{3,24}\.blob\.core\.windows\.net\/[^\s\"']+",
    "AliCloud OSS URI": r"https?:\/\/[a-z0-9\-]+\.oss(-[a-z]+)?\.aliyuncs\.com\/[^\s\"']+",
    "Tencent COS URI": r"https:\/\/[a-z0-9\-]+\.cos\.[a-z0-9\-]+\.myqcloud\.com\/[^\s\"']+",

    # Login + Password Patterns
    "Username:Password Combo": r"\b(?:user(name)?|login)[=:]\s*[\"']?[a-zA-Z0-9._%-]{3,32}[\"']?[\s,;]+(?:pass(word)?)[=:]\s*[\"']?.{4,64}[\"']?",
    "Basic Auth in URL": r"https?:\/\/[^:\/\s]+:[^@\/\s]+@[^\/\s]+",
    "Hardcoded Credentials": r"(?i)(user(name)?|login|pass(word)?)\s*[:=]\s*[\"']?[a-zA-Z0-9._%\-!@#$^&*()+=]{4,64}[\"']?",

    # UI-based or embedded credentials and endpoints
    "Jupyter Notebook Token URL": r"http:\/\/127\.0\.0\.1:8888\/\?token=[a-f0-9]{48,64}",
    "Streamlit Secret Key": r"(?i)(st_secrets|streamlit_secrets)\s*[:=]\s*[\"']?.{8,64}[\"']?",
    "Gradio API Key": r"(?i)(gradio_api_key|gr_key)\s*[:=]\s*[\"']?[A-Za-z0-9\-_=]{20,64}[\"']?",
    "HuggingFace Token": r"hf_[A-Za-z0-9]{32,64}",
    "JupyterHub URL": r"https?:\/\/[a-z0-9\-\.]+\/hub\/login(\?next=.*)?",
    "Login HTML Form": r"<form[^>]*action=['\"]?\/?(login|signin)[^>]*>",
    "Notebook Inline Password": r"(?i)(password|token)\s*=\s*[\"']?.{6,64}[\"']?",
    "Flask Secret Key": r"app\.config\[['\"]SECRET_KEY['\"]\]\s*=\s*[\"'][a-zA-Z0-9!@#$%^&*()_+]{16,128}[\"']",
    "Django Secret Key": r"(?i)SECRET_KEY\s*=\s*[\"']?[a-zA-Z0-9!@#$%^&*()_+]{16,128}[\"']?",
    "FastAPI API Key Header": r"(?i)(x-api-key|authorization)\s*[:=]\s*[\"']?[A-Za-z0-9\-_]{16,64}[\"']?",
    "OAuth Redirect URI": r"https?:\/\/[a-z0-9\-\.]+\/(auth|oauth|callback)[^\s\"']*",
    "Web Login UI Button": r"<button[^>]*>(Log ?In|Sign ?In|Authenticate)[^<]*<\/button>",
    "Notebook Commented Key": r"#.*(api[_-]?key|token|password)[^=\n]*=[^\n]+",
    "Javascript Login Code": r"(fetch|axios|XMLHttpRequest)\([^)]*(\/login|\/auth)[^)]*\)",
    "CLI Auth Command": r"(curl|wget|http|python3?) .* (\/token|\/login|--auth)",

      # 🐳 Docker & CLI Auth
    "Docker Login": r"docker\s+login\s+(-u\s+\S+\s+-p\s+\S+|--username\s+\S+\s+--password\s+\S+)",
    "Docker Config JSON": r'"auths"\s*:\s*{\s*".*?"\s*:\s*{\s*"auth"\s*:\s*"[A-Za-z0-9+/=]+"',
    "Container Registry Token": r"(ghcr|ecr|gcr|docker)\.io\/token\?service=.*",

    # ☁️ Kubernetes & kubectl
    "kubectl Set Credentials": r"kubectl\s+config\s+set-credentials\s+\S+\s+--token=\S+",
    "kubectl Kubeconfig Leak": r"apiVersion:\s+v1\s+clusters:.*users:.*token:",
    "Kube API Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",  # JWT
    "Helm Repository Auth": r"helm\s+repo\s+add\s+\S+\s+https:\/\/.*\s+--username\s+\S+\s+--password\s+\S+",

    # 🔐 HashiCorp Vault / Secrets
    "Vault Login Command": r"vault\s+login\s+[-\-]token=\S+",
    "Vault Token Leak": r"VAULT_TOKEN\s*=\s*[\"']?[a-z0-9\-]{16,64}[\"']?",
    "Vault Env Export": r"export\s+VAULT_TOKEN=[a-z0-9\-]{16,64}",

    # 🧰 GCP CLI Auth
    "gcloud Auth Login": r"gcloud\s+auth\s+activate-service-account\s+--key-file=\S+",
    "GCP Access Token": r"ya29\.[A-Za-z0-9\-_]+",  # typical OAuth token format
    "GCP Bearer Token Header": r"Authorization:\s*Bearer\s+ya29\.[A-Za-z0-9\-_]+",

    # ☁️ AWS CLI
    "AWS CLI Export": r"export\s+(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)=[\"']?[A-Za-z0-9/\+=]{16,128}[\"']?",
    "AWS Credentials File": r"\[default\]\s+aws_access_key_id\s*=\s*\S+\s+aws_secret_access_key\s*=\s*\S+",

    # ☁️ Azure CLI
    "Azure Login": r"az\s+login\s+--service-principal\s+--username\s+\S+\s+--password\s+\S+",
    "Azure Secret in Env": r"AZURE_(CLIENT_SECRET|TENANT_ID|SUBSCRIPTION_ID)\s*=\s*[\"']?\S{8,64}[\"']?",

    # 🪪 Identity Tokens / Sessions
    "JWT Token (Generic)": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
    "Basic Auth Header": r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,128}",
    "Bearer Auth Header": r"Authorization:\s*Bearer\s+[A-Za-z0-9-_]{20,512}",

    # 📡 Webhook + Web API
    "Webhook Secret": r"webhook(_secret|_token)?\s*[:=]\s*[\"']?[A-Za-z0-9\-_=]{8,128}[\"']?",
    "Public Webhook Exposure": r"https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+",

    # 🧠 AI Platform Tokens (Creative)
    "OpenAI Key": r"sk-[A-Za-z0-9]{32,48}",
    "DeepL API Key": r"auth_key\s*[:=]\s*[\"']?[a-zA-Z0-9\-]{30,45}[\"']?",
    "Cohere Token": r"cohere\.Client\(['\"]?[a-z0-9\-]{20,64}['\"]?\)",
    "Anthropic API Key": r"cla-[A-Za-z0-9]{32,64}",
    
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "OpenAI Key": r"sk-[a-zA-Z0-9]{32,}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Generic Secret": r"(secret|password|pass|pwd)[\s:=]+[^\s\'\"\\]{6,}",
    "S3 URI": r"s3://[a-zA-Z0-9\-_./]+",
    "Mongo URI": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^ \n]+",
    "Basic Auth": r"Authorization:\s*Basic\s+[a-zA-Z0-9+/=]{16,}",
    "Base64 block": r"[A-Za-z0-9+/]{40,}={0,2}",
}

# ✅ Encoding patterns that hide intent (unicode obfuscation, morse)
ENCODED_INPUT_PATTERNS = [
    r"(\\u[0-9a-fA-F]{4})",           # Unicode escapes
    r"([.-]{1,2}\s*){5,}",            # Morse-like
    r"[\U0001F600-\U0001F64F]{3,}",   # Emoji
    r"(zWJ|zwj|zero-width)",          # Zero-width joiner patterns
]


MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D',
    '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
    '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
    '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1',
    '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9'
}

# Basic emoji to ASCII mapping (customize this!)
EMOJI_MAP = {
    "🅰️": "A", "🅱️": "B", "🆎": "AB", "🆑": "CL", "🆘": "SOS",
    "🔤": "ABC", "🆔": "ID", "🔞": "18+", "🔠": "A"
}

# Zero-width char range
ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF]")

# Add Advanced Jabralink Detection Patterns
JABRALINK_PATTERNS = [
    r"[\u200B-\u200D\uFEFF]",  # Zero-width
    r"[^\x00-\x7F]{3,}",       # Unicode script abuse (≥3 non-ASCII)
    r"[\u0300-\u036F]{2,}",    # Zalgo combining marks
    r"(🅰️|🅱️|🆎|🆔|🔠|🆘)",         # Emoji substitution abuse
    r"(ignore|override|prompt)[\W_]{0,3}(again|all|filters)",  # Jabralink phrasing
    r"(invis|whis|echo|speak|subvocal|inject).*prompt",         # Audio prompt bait
    r"(morse|base64|hex).*(command|code|payload)",              # Encoded intent
    r"(curl|wget).*\|.*(sh|bash)",                              # Embedded remote command
]

def normalize_unicode(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def match_any(patterns: List[str], text: str) -> List[str]:
    matches = []
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            matches.append(pat)
    return matches


def scan_prompt(prompt: str) -> Dict:
    """Main scanner function."""
    report = {
        "prompt_injection": False,
        "jailbreak": False,
        "secrets_found": [],
        "pii_found": [],
        "remote_exec_risk": False,
        "encoding_obfuscation": False,
        "jabralink_detected": False,
        "score": 0.0,
        "alerts": []
    }

    norm_prompt = normalize_unicode(prompt)

    # Prompt Injection
    inj = match_any(PROMPT_INJECTION_PATTERNS, norm_prompt)
    if inj:
        report["prompt_injection"] = True
        report["alerts"].append("⚠️ Prompt Injection Detected")

    # Jailbreak / Obfuscation
    jail = match_any(ENCODED_INPUT_PATTERNS, prompt)
    if jail:
        report["jailbreak"] = True
        report["alerts"].append("🛑 Obfuscated / Jailbreak Payload")

    # Morse Trigger (basic presence)
    if re.search(r"[.-]{3,}", prompt):
        report["alerts"].append("📡 Morse-like pattern detected")

    # Emoji translation abuse
    if any(e in prompt for e in EMOJI_MAP.keys()):
        report["alerts"].append("🔣 Emoji-substitution detected")

    # Zero-width encoding
    if ZERO_WIDTH_RE.search(prompt):
        report["encoding_obfuscation"] = True
        report["alerts"].append("🕵️‍♂️ Zero-width encoding used")

    # Jabralink-style attack
    if match_any(JABRALINK_PATTERNS, prompt):
        report["jabralink_detected"] = True
        report["alerts"].append("🧬 Jabralink-style covert injection")

    # Secrets
    for label, pattern in PII_PATTERNS.items():
        if re.search(pattern, norm_prompt):
            report["secrets_found"].append(label)
            report["alerts"].append(f"🔐 Potential {label} detected")

    # PII
    for label, pattern in PII_PATTERNS.items():
        if re.search(pattern, norm_prompt):
            report["pii_found"].append(label)
            report["alerts"].append(f"🔐 Potential {label} detected")

    # Remote exec
    if match_any(REMOTE_EXEC_PATTERNS, norm_prompt):
        report["remote_exec_risk"] = True
        report["alerts"].append("🚨 Remote Execution Pattern")

    # Score
    score = (
        int(report["prompt_injection"]) * 0.2 +
        int(report["jailbreak"]) * 0.2 +
        int(report["jabralink_detected"]) * 0.2 +
        len(report["secrets_found"]) * 0.1 +
        len(report["pii_found"]) * 0.1 +
        int(report["encoding_obfuscation"]) * 0.1 +
        int(report["remote_exec_risk"]) * 0.1
    )
    report["score"] = min(score, 1.0)

    if not report["alerts"]:
        report["alerts"].append("✅ No major threat indicators")

    return report
