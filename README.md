# Phishing Email Detector

A Python tool that analyzes email text and flags phishing attempts by
checking for suspicious phrases, IP-based links, and look-alike domains.

## Features
- Detects common phishing phrases (e.g. "verify your account", "urgent")
- Flags links that use raw IP addresses instead of domain names
- Flags look-alike domains (e.g. paypa1-secure.com instead of paypal.com)
- Gives a verdict: SAFE, SUSPICIOUS, or PHISHING with a risk score

## Requirements
- Python 3
- tldextract

## Installation
pip3 install tldextract --break-system-packages

## Usage
python3 detector.py

Paste the email text, then press Enter on an empty line to analyze it.

## How it works
The script scores the email based on suspicious keyword matches (+1 each)
and risky links (+3 each for IP-based or look-alike domains). A score of
0 is SAFE, 1-2 is SUSPICIOUS, 3+ is PHISHING.

## Limitations
- Domain matching is simple and can miss advanced typosquatting
  (e.g. letter-to-number substitutions like paypa1 vs paypal).
- Keyword list is not exhaustive; a well-crafted phishing email without
  these phrases may be missed.
- This is intended for educational/awareness purposes only, not as a
  production-grade email security tool.

## Author
Mohammed Sanaan

