Data Extraction & Secure Validation:

Regex-based tool that extracts structured data from raw, messy text (simulating a support-ticket export from an external API) and rejects hostile or malformed input instead of trusting it.

What it extracts:

Emails (with special classification for ALU domains: official, alumni, SI), credit card numbers (format-checked and Luhn-validated), URLs (with or without a protocol), and phone numbers. Also extracts hashtags and times (12-hour and 24-hour) as bonus data types.

How to run:

Run the following commands;
cd alu-regex-data-extraction_aantulay
python3 src/main.py input/raw-text.txt

Security:

Every line is screened for SQL injection, script tags, path traversal, and prompt-injection-style text before extraction runs. Flagged lines are skipped entirely, not "cleaned." Emails and card numbers are masked (e.g. j******o@alueducation.com, **** **** **** 6467) before they're ever printed or written to disk — the full values never touch the console or the output file.