import requests

def check_a02(target):
    findings = []

    if not target.startswith("http"):
        target = "http://" + target

    if not target.startswith("https"):
        findings.append("Site does not enforce HTTPS")

    try:
        r = requests.get(target, timeout=5)
        headers = r.headers

        if "Strict-Transport-Security" not in headers:
            findings.append("HSTS header missing")

    except:
        pass

    return findings
