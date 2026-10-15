import re
import tldextract

SUSPICIOUS_WORDS = [
    "urgent", "verify your account", "suspended", "click here",
    "confirm your password", "update your information", "act now",
    "limited time", "winner", "claim your prize", "bank account",
    "unusual activity", "login immediately", "security alert"
]

TRUSTED_DOMAINS = [
    "google.com", "paypal.com", "amazon.com", "microsoft.com",
    "apple.com", "facebook.com", "instagram.com"
]

def extract_links(text):
    return re.findall(r'https?://[^\s<>"\']+', text)

def is_ip_based(url):
    return bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))

def domain_similarity(url):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    for trusted in TRUSTED_DOMAINS:
        trusted_name = trusted.split(".")[0]
        if trusted_name in domain and domain != trusted:
            return domain
    return None

def analyze_email(text):
    score = 0
    reasons = []

    lower_text = text.lower()
    for word in SUSPICIOUS_WORDS:
        if word in lower_text:
            score += 1
            reasons.append(f"Suspicious phrase found: '{word}'")

    links = extract_links(text)
    for link in links:
        if is_ip_based(link):
            score += 3
            reasons.append(f"Link uses raw IP address: {link}")

        fake_domain = domain_similarity(link)
        if fake_domain:
            score += 3
            reasons.append(f"Suspicious look-alike domain: {fake_domain}")

    if score == 0:
        verdict = "SAFE"
    elif score <= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "PHISHING"

    return verdict, score, reasons

def main():
    print("=== Phishing Email Detector ===")
    print("Email ka text paste karo, phir khali line pe Enter dabao:\n")

    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)

    email_text = "\n".join(lines)
    verdict, score, reasons = analyze_email(email_text)

    print("\n--- Result ---")
    print(f"Verdict: {verdict}")
    print(f"Risk Score: {score}")
    if reasons:
        print("Reasons:")
        for r in reasons:
            print(f"  - {r}")
    else:
        print("Koi suspicious cheez nahi mili.")

if __name__ == "__main__":
    main()

