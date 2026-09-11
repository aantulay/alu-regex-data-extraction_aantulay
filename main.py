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