from core.banner import show_banner
from vulns.access_control import check_a01
from vulns.crypto_failures import check_a02
from vulns.injection import check_a03
from vulns.security_misconfig import check_a05


def print_results(results, owasp_id):
    if results:
        print(f"\n[!] Possible {owasp_id} issues:")
        for r in results:
            print("  -", r)
    else:
        print(f"\n[✓] No obvious {owasp_id} vulnerabilities found.")


def run_full_scan(target):
    print("\n[+] Running Full OWASP Scan...")

    print("\n[+] A01 - Broken Access Control")
    print_results(check_a01(target), "A01")

    print("\n[+] A02 - Cryptographic Failures")
    print_results(check_a02(target), "A02")

    print("\n[+] A03 - Injection")
    print_results(check_a03(target), "A03")

    print("\n[+] A05 - Security Misconfiguration")
    print_results(check_a05(target), "A05")


def run_selected_scan(target):
    print("\nSelect vulnerabilities to scan (comma separated):")
    print("1. A01 - Broken Access Control")
    print("2. A02 - Cryptographic Failures")
    print("3. A03 - Injection")
    print("4. A05 - Security Misconfiguration")

    choice = input("\nEnter your choice (e.g. 1,3): ").strip()

    mapping = {
        "1": ("A01", check_a01),
        "2": ("A02", check_a02),
        "3": ("A03", check_a03),
        "4": ("A05", check_a05),
    }

    selected = [c.strip() for c in choice.split(",")]

    for c in selected:
        if c in mapping:
            owasp_id, func = mapping[c]
            print(f"\n[+] Running {owasp_id} check...")
            print_results(func(target), owasp_id)
        else:
            print(f"[!] Invalid option skipped: {c}")


def main():
    show_banner()

    target = input("Enter target domain or IP: ").strip()
    print(f"\n[+] Target set to: {target}")

    while True:
        print("\nChoose scan mode:")
        print("1. Full vulnerability scan")
        print("2. Select specific vulnerabilities")
        print("3. Exit")

        option = input("\nEnter option: ").strip()

        if option == "1":
            run_full_scan(target)
        elif option == "2":
            run_selected_scan(target)
        elif option == "3":
            print("\nExiting STONER. Stay safe")
            break
        else:
            print("[!] Invalid option. Try again.")


if __name__ == "__main__":
    main()
