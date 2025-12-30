#!/usr/bin/env python3

import argparse
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
    print("\n[+] Running Full OWASP Scan")

    print("\n[+] A01 - Broken Access Control")
    print_results(check_a01(target), "A01")

    print("\n[+] A02 - Cryptographic Failures")
    print_results(check_a02(target), "A02")

    print("\n[+] A03 - Injection")
    print_results(check_a03(target), "A03")

    print("\n[+] A05 - Security Misconfiguration")
    print_results(check_a05(target), "A05")


def run_selected(target, args):
    if args.a01:
        print("\n[+] A01 - Broken Access Control")
        print_results(check_a01(target), "A01")

    if args.a02:
        print("\n[+] A02 - Cryptographic Failures")
        print_results(check_a02(target), "A02")

    if args.a03:
        print("\n[+] A03 - Injection")
        print_results(check_a03(target), "A03")

    if args.a05:
        print("\n[+] A05 - Security Misconfiguration")
        print_results(check_a05(target), "A05")


def main():
    parser = argparse.ArgumentParser(
        description="STONER - OWASP Top 10 Vulnerability Scanner"
    )

    parser.add_argument(
        "target",
        help="Target domain or IP (example: example.com)"
    )

    parser.add_argument("--full", action="store_true", help="Run full scan")
    parser.add_argument("--a01", action="store_true", help="Scan A01")
    parser.add_argument("--a02", action="store_true", help="Scan A02")
    parser.add_argument("--a03", action="store_true", help="Scan A03")
    parser.add_argument("--a05", action="store_true", help="Scan A05")

    args = parser.parse_args()

    show_banner()
    print(f"[+] Target: {args.target}")

    if args.full:
        run_full_scan(args.target)
    elif any([args.a01, args.a02, args.a03, args.a05]):
        run_selected(args.target, args)
    else:
        print("\n[!] No scan option selected")
        print("    Use --full or specific flags like --a01 --a03")


if __name__ == "__main__":
    main()
