#!/usr/bin/env python3
"""
Features:
- TCP connect scan
- Thread pool concurrency
- Service detection (basic)
- Banner grabbing
- Timeouts & graceful handling
"""

from _future_ import annotations

import socket
import concurrent.futures
from dataclasses import dataclass
from typing import List, Optional, Tuple


# -------------------- Models --------------------

@dataclass(frozen=True)
class ScanResult:
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None


# -------------------- Core Scanner --------------------

class PortScanner:
    def _init_(
        self,
        target: str,
        ports: List[int],
        timeout: float = 1.0,
        workers: int = 200,
        grab_banner: bool = True,
    ):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.grab_banner = grab_banner

    # ---- public API ----
    def scan(self) -> List[ScanResult]:
        results: List[ScanResult] = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:
            futures = {
                executor.submit(self._scan_port, port): port
                for port in self.ports
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        return sorted(results, key=lambda r: r.port)

    # ---- internal ----
    def _scan_port(self, port: int) -> Optional[ScanResult]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.target, port))

                service = self._detect_service(port)
                banner = self._grab_banner(sock) if self.grab_banner else None

                return ScanResult(
                    port=port,
                    is_open=True,
                    service=service,
                    banner=banner,
                )

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        try:
            sock.sendall(b"\r\n")
            data = sock.recv(1024)
            return data.decode(errors="ignore").strip() or None
        except OSError:
            return None

    @staticmethod
    def _detect_service(port: int) -> Optional[str]:
        COMMON_SERVICES = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http-proxy",
        }
        return COMMON_SERVICES.get(port)


# -------------------- Utils --------------------

def parse_ports(port_range: str) -> List[int]:
    """
    Examples:
    22
    1-1024
    22,80,443
    """
    ports = set()

    for part in port_range.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


# -------------------- CLI --------------------

if _name_ == "_main_":
    import argparse

    parser = argparse.ArgumentParser(description="Senior TCP Port Scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024", help="Ports (e.g. 22,80,443 or 1-1024)"
    )
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    parser.add_argument("-w", "--workers", type=int, default=200)
    parser.add_argument("--no-banner", action="store_true")

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    scanner = PortScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        grab_banner=not args.no_banner,
    )

    results = scanner.scan()

    for r in results:
        print(
            f"[OPEN] {r.port:<5} "
            f"{(r.service or 'unknown'):<10} "
            f"{r.banner or ''}"
        )