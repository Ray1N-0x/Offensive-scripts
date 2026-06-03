#!/usr/bin/env python3

import requests
import sys

HEADERS = [
	'Strict-Transport-Security',
	'Content-Security-Policy',
	'X-Frame-Options',
	'X-Content-Type-Options',
	'Referrer-Policy'
]

def check_headers(url):
	if not url.startwith('http'):
		url = f'https://{url}'
	try:
		resp = requests.get(url, timeout=10)
		print(f"\n[+] {url} ({resp.status_code})\n")
		for h in HEADERS:
			value = resp.headers.get(h)
			status = "OK" if value else "NO"
			print(f" {status} {h}: {value if value else 'missing'}")
	except Exception as e:
		print(f"[-] ERROR: {e}")

if __name__ == "__main__":
	target = sys.argv[1] if len(sys.argv) > 1 else input("URL: ")
	chech_headers(target)
