import requests

def check_a01(target):
    findings = []

    if not target.startswith("http"):
        target = "http://" + target

    paths = ["/admin", "/dashboard", "/config", "/backup"]

    for path in paths:
        try:
            r = requests.get(target + path, timeout=5)
            if r.status_code == 200:
                findings.append(f"Accessible restricted path: {target}{path}")
        except:
            pass

    return findings
