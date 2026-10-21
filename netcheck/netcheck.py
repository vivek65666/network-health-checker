#!/usr/bin/env python3
"""Network Health Checker: DNS, TCP, HTTP and TLS checks with logging and alerts."""
import argparse
import logging
import socket
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

logging.basicConfig(
    filename="netcheck.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

DEFAULT_TARGETS = ["google.com", "github.com", "akamai.com"]


def check_dns(host):
    start = time.time()
    ip = socket.gethostbyname(host)  # DNS resolution
    return ip, (time.time() - start) * 1000


def check_tcp(ip, port=443, timeout=5):
    start = time.time()
    with socket.create_connection((ip, port), timeout=timeout):  # TCP handshake
        pass
    return (time.time() - start) * 1000

def check_http(host, timeout=5):
    start = time.time()
    req = urllib.request.Request(
        f"https://{host}",
        headers={"User-Agent": "Mozilla/5.0 (compatible; netcheck/1.0)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code  # server replied, so report the status code
    return status, (time.time() - start) * 1000

def check_tls(host, port=443, timeout=5):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (expiry - datetime.now(timezone.utc)).days
    return version, days_left


def check_host(host, latency_limit_ms, cert_days_limit):
    results = {"host": host, "ok": True, "alerts": []}
    try:
        ip, dns_ms = check_dns(host)
        tcp_ms = check_tcp(ip)
        status, http_ms = check_http(host)
        tls_version, days_left = check_tls(host)
        results.update(ip=ip, dns_ms=dns_ms, tcp_ms=tcp_ms, status=status,
                       http_ms=http_ms, tls=tls_version, cert_days=days_left)
        if status >= 400:
            results["alerts"].append(f"HTTP status {status}")
        if http_ms > latency_limit_ms:
            results["alerts"].append(f"Slow HTTP {http_ms:.0f}ms > {latency_limit_ms}ms")
        if days_left < cert_days_limit:
            results["alerts"].append(f"TLS cert expires in {days_left} days")
    except Exception as exc:  # DNS failure, timeout, TLS error, etc.
        results["ok"] = False
        results["alerts"].append(f"Check failed: {exc}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Network health checker")
    parser.add_argument("hosts", nargs="*", default=DEFAULT_TARGETS)
    parser.add_argument("--latency", type=int, default=1500, help="HTTP latency alert (ms)")
    parser.add_argument("--cert-days", type=int, default=14, help="TLS expiry alert (days)")
    args = parser.parse_args()

    for host in args.hosts:
        r = check_host(host, args.latency, args.cert_days)
        if r["ok"]:
            line = (f"[{host}] IP={r['ip']} DNS={r['dns_ms']:.0f}ms TCP={r['tcp_ms']:.0f}ms "
                    f"HTTP={r['status']} ({r['http_ms']:.0f}ms) {r['tls']} cert={r['cert_days']}d")
            print(line)
            logging.info(line)
        for alert in r["alerts"]:
            print(f"  ALERT [{host}] {alert}")
            logging.warning(f"[{host}] {alert}")


if __name__ == "__main__":
    main()