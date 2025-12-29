import requests

def check_a03(target):
    findings = []

    if not target.startswith("http"):
        target = "http://" + target

    params = ["id", "q", "search", "page", "cat"]
    sql_payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
    xss_payload = "<script>alert(1)</script>"

    sql_errors = [
        "sql syntax",
        "mysql",
        "warning",
        "ora-",
        "postgresql",
        "sqlite",
        "syntax error"
    ]

    try:
        for param in params:

            # ---- SQL Injection ----
            for payload in sql_payloads:
                url = f"{target}?{param}={payload}"
                r = requests.get(url, timeout=5)

                for err in sql_errors:
                    if err in r.text.lower():
                        findings.append(
                            f"Possible SQL Injection via parameter '{param}'"
                        )
                        break

            # ---- Reflected XSS ----
            xss_url = f"{target}?{param}={xss_payload}"
            r = requests.get(xss_url, timeout=5)

            if xss_payload.lower() in r.text.lower():
                findings.append(
                    f"Possible Reflected XSS via parameter '{param}'"
                )

    except:
        pass

    return list(set(findings))
