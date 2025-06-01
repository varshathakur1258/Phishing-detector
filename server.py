from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
import whois

app = Flask(__name__)

# Simple phishing detection based on URL patterns
def is_phishing_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url
        parsed_url = urlparse(url)

    checks = {
        "contains_ip": re.search(r"\d{1,3}(\.\d{1,3}){3}", parsed_url.netloc) is not None,
        "contains_at": "@" in url,
        "too_many_dots": parsed_url.netloc.count('.') > 3,
        "contains_dash": "-" in parsed_url.netloc,
        "shortener": any(short in parsed_url.netloc for short in ["bit.ly", "tinyurl", "t.co"]),
    }
    return any(checks.values()), checks

# WHOIS domain info lookup
def get_domain_info(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = url
        w = whois.whois(domain)
        return {
            "domain": domain,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "registrar": w.registrar,
            "country": w.country
        }
    except Exception as e:
        return {"error": str(e)}

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    details = None
    domain_info = None
    if request.method == "POST":
        url = request.form.get("url")
        is_phish, checks = is_phishing_url(url)
        result = "⚠️ Phishing Detected!" if is_phish else "✅ URL appears safe."
        details = checks
        domain_info = get_domain_info(url)
    return render_template("index.html", result=result, details=details, domain_info=domain_info)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
