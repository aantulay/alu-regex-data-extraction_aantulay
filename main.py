import re
import sys
import json
import os

# Hostile input screening:
# Lines matching these are excluded from extraction entirely

SUSPICIOUS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"--\s*$"),
    re.compile(r"\.\./\.\./"),
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"\b(rm\s+-rf|os\.system|eval\()", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
]

def is_suspicious(line: str) -> bool:
    return any(pat.search(line) for pat in SUSPICIOUS_PATTERNS)

# Extraction patterns

# Email: local@domain.tld. Won't match "@@" or a comma for a dot.
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
 
ALU_DOMAINS = {
    "alueducation.com": "ALU official",
    "alumni.alueducation.com": "ALU alumni",
    "si.alueducation.com": "ALU SI",
}
 
# URL: http(s):// or bare www., with optional path/query.
URL_RE = re.compile(
    r"\b(?:https?://[A-Za-z0-9.-]+|www\.[A-Za-z0-9.-]+)\.[A-Za-z]{2,}(?:/[^\s<>\"']*)?"
)
 
# Trailing sentence punctuation to strip off a matched URL.
URL_TRAILING_PUNCT_RE = re.compile(r"[.,;:!?)\]\"']+$")
 
# Phone: optional country code, optional area code, then digit groups.
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]\d{3,4}(?:[\s.-]?\d{3})?(?!\d)"
)
 
# Credit card: 13-19 digits, optionally grouped with spaces/dashes.
# Format check only; luhn_valid() below confirms real validity.
CREDIT_CARD_RE = re.compile(
    r"\b(?:\d[ -]?){13,19}\b"
)
 
# Hashtag: # + letters/digits/underscore, must start with a letter.
HASHTAG_RE = re.compile(r"#[A-Za-z][A-Za-z0-9_]*")
 
# Time: 24h or 12h with optional AM/PM (space only consumed if AM/PM present).
TIME_RE = re.compile(
    r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s?[AaPp][Mm])?\b"
)