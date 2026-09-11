#!/usr/bin/env python3

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

def luhn_valid(card_digits: str) -> bool:
    """Standard Luhn checksum."""
    digits = [int(d) for d in card_digits]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0
 
 
def mask_email(email: str) -> str:
    """e.g. jotieno@alueducation.com -> j*****o@alueducation.com"""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*" * max(len(local) - 1, 1)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"
 
 
def mask_card(card_digits: str) -> str:
    """e.g. 4539148803436467 -> **** **** **** 6467"""
    last4 = card_digits[-4:]
    remaining = len(card_digits) - 4
    group_count = -(-remaining // 4)  # ceil division
    groups = ["****"] * max(group_count, 1)
    return " ".join(groups + [last4])
 
 
def classify_email(email: str) -> str:
    domain = email.split("@")[-1].lower()
    return ALU_DOMAINS.get(domain, "external")
 
 
def extract(text: str) -> dict:
    results = {
        "emails": [],
        "urls": [],
        "phone_numbers": [],
        "credit_cards": [],
        "hashtags": [],
        "times": [],
        "security": {
            "lines_scanned": 0,
            "lines_flagged_and_skipped": 0,
        },
    }
 
    seen_emails, seen_urls, seen_phones = set(), set(), set()
    seen_cards, seen_hashtags, seen_times = set(), set(), set()
 
    for raw_line in text.splitlines():
        results["security"]["lines_scanned"] += 1
 
        # Hostile lines are skipped entirely, not sanitized.
        if is_suspicious(raw_line):
            results["security"]["lines_flagged_and_skipped"] += 1
            continue
 
        # Emails
        for m in EMAIL_RE.findall(raw_line):
            if m not in seen_emails:
                seen_emails.add(m)
                results["emails"].append({
                    "value": mask_email(m),
                    "classification": classify_email(m),
                })
 
        # URLs
        for m in URL_RE.findall(raw_line):
            cleaned = URL_TRAILING_PUNCT_RE.sub("", m)
            if cleaned not in seen_urls:
                seen_urls.add(cleaned)
                results["urls"].append({
                    "value": cleaned,
                    "secure": cleaned.startswith("https://"),
                    "protocol_specified": cleaned.startswith(("http://", "https://")),
                })
 
        # Credit cards first, then blank matches out before phone matching
        # so a long card number can't get re-split into "phone numbers".
        line_for_phones = raw_line
        for card_match in CREDIT_CARD_RE.finditer(raw_line):
            m = card_match.group()
            digits = re.sub(r"[ -]", "", m)
            if len(digits) < 13 or len(digits) > 19:
                continue
            line_for_phones = line_for_phones.replace(m, "C" * len(m))
            if digits in seen_cards:
                continue
            seen_cards.add(digits)
            results["credit_cards"].append({
                "value": mask_card(digits),
                "luhn_valid": luhn_valid(digits),
            })
 
        # Phone numbers
        for m in PHONE_RE.findall(line_for_phones):
            cleaned = m.strip()
            digit_count = len(re.sub(r"\D", "", cleaned))
            if digit_count < 7:
                continue
            if cleaned not in seen_phones:
                seen_phones.add(cleaned)
                results["phone_numbers"].append({"value": cleaned})
 
        # Hashtags
        for m in HASHTAG_RE.findall(raw_line):
            if m not in seen_hashtags:
                seen_hashtags.add(m)
                results["hashtags"].append(m)
 
        # Times
        for m in TIME_RE.findall(raw_line):
            if m not in seen_times:
                seen_times.add(m)
                results["times"].append(m)
 
    return results
 
 
def print_summary(results: dict) -> None:
    """All values here are already masked, so this is always safe to log."""
    print("=== Extraction Summary ===")
    print(f"Lines scanned:        {results['security']['lines_scanned']}")
    print(f"Lines flagged/skipped:{results['security']['lines_flagged_and_skipped']}")
    print()
    print(f"Emails found:         {len(results['emails'])}")
    for e in results["emails"]:
        print(f"   {e['value']}  [{e['classification']}]")
    print(f"URLs found:           {len(results['urls'])}")
    for u in results["urls"]:
        if not u["protocol_specified"]:
            flag = "no protocol specified"
        elif u["secure"]:
            flag = "secure"
        else:
            flag = "INSECURE (http)"
        print(f"   {u['value']}  [{flag}]")
    print(f"Phone numbers found:  {len(results['phone_numbers'])}")
    for p in results["phone_numbers"]:
        print(f"   {p['value']}")
    print(f"Credit cards found:   {len(results['credit_cards'])}")
    for c in results["credit_cards"]:
        status = "valid (Luhn)" if c["luhn_valid"] else "INVALID (failed Luhn)"
        print(f"   {c['value']}  [{status}]")
    print(f"Hashtags found:       {len(results['hashtags'])}")
    print(f"   {', '.join(results['hashtags'])}")
    print(f"Times found:          {len(results['times'])}")
    print(f"   {', '.join(results['times'])}")
 
 
def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else "input/raw-text.txt"
    if not os.path.exists(input_path):
        print(f"Input file not found: {input_path}")
        sys.exit(1)
 
    with open(input_path, "r", encoding="utf-8") as f:
        text = f.read()
 
    results = extract(text)
    print_summary(results)
 
    out_path = os.path.join("output", "sample-output.json")
    os.makedirs("output", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results (masked) written to {out_path}")
 
 
if __name__ == "__main__":
    main()