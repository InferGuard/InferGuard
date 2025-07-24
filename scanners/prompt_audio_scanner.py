import whisper
import re
import numpy as np
from scipy.io import wavfile
from scipy.fft import rfft, rfftfreq

# ---------------------
# Configurable Patterns
# ---------------------

JABRALINK_PATTERNS = [
    r"ignore.*(instructions|guardrails|safety)",
    r"simulate.*terminal",
    r"bash|curl|wget.*\|.*sh",
    r"(you are now DAN|pretend|disregard all previous)",
    r"(morse|base64|emoji|subvocal|hidden command)",
]

PROMPT_INJECTION_PATTERNS = [
    r"(ignore|disregard).*(previous|earlier).*instructions",
    r"(pretend|assume).*(you are not|you are now)",
    r"#system", r"#ignore", r"\bforget\b.*prompt"
]

# ---------------------
# 1. Transcribe + Scan
# ---------------------

def is_audio_jabralink(audio_path: str) -> bool:
    model = whisper.load_model("base")
    result = model.transcribe(audio_path)
    text = result.get("text", "").strip().lower()
    jabra_hits = match_any(JABRALINK_PATTERNS, text)
    injection_hits = match_any(PROMPT_INJECTION_PATTERNS, text)
    if jabra_hits or injection_hits:
        print("❌ Jabralink-style prompt injection detected in transcription")
        return True
    return False

# -------------------------------
# 2. Spectrogram Morse Detection
# -------------------------------

def detect_morse_like_pattern(audio_path: str) -> bool:
    sr, data = wavfile.read(audio_path)
    if len(data.shape) > 1:
        data = data[:, 0]
    data = data / np.max(np.abs(data))
    bursts = np.where(np.abs(data) > 0.3)[0]
    if len(bursts) > 100:
        print("⚠️ Suspicious pulse pattern detected (Morse-like)")
        return True
    return False

# -----------------------------------
# 3. Whisper-Frequency Band Analysis
# -----------------------------------

def detect_whispered_content(audio_path: str) -> bool:
    sr, data = wavfile.read(audio_path)
    if len(data.shape) > 1:
        data = data[:, 0]
    data = data / np.max(np.abs(data))
    fft = rfft(data)
    freqs = rfftfreq(len(data), 1 / sr)
    whisper_band_energy = np.sum(np.abs(fft[(freqs > 2000) & (freqs < 8000)]))
    total_energy = np.sum(np.abs(fft))
    if whisper_band_energy / total_energy > 0.6:
        print("⚠️ High whisper-band energy ratio detected")
        return True
    return False

# -----------------------
# Pattern Match Helper
# -----------------------

def match_any(patterns, text):
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)

# -----------------------
# Final Firewall Decision
# -----------------------

def audio_upload_firewall(audio_path: str) -> bool:
    if is_audio_jabralink(audio_path):
        return False
    if detect_morse_like_pattern(audio_path):
        return False
    if detect_whispered_content(audio_path):
        return False
    print("✅ Audio passed all filters")
    return True
