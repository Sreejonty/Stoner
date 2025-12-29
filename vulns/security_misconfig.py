import requests

def check_a05(target):
    findings = []

    if not target.startswith("http"):
        target = "http://" + target

    try:
        r = requests.get(target, timeout=5)
        headers = r.headers

        if "Server" in headers:
            findings.append(f"Server header exposed: {headers['Server']}")

        if "X-Powered-By" in headers:
            findings.append(f"X-Powered-By header exposed: {headers['X-Powered-By']}")

    except:
        pass

    return findings
