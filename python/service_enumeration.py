#!/usr/bin/env python3
"""
Features:
- HTTP/HTTPS header enumeration
- SSH / FTP banner grabbing
- Extensible service probes
- Clean architecture (no script-kasha)
"""

from _future_ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Dict


# -------------------- Models --------------------

@dataclass(frozen=True)
class ServiceInfo:
    port: int
    service: str
    banner: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None


# -------------------- Core --------------------

class ServiceEnumerator:
    def _init_(self, target: str, timeout: float = 2.0):
        self.target = target
        self.timeout = timeout

    def enumerate(self, port: int) -> Optional[ServiceInfo]:
        if port in (80, 8080):
            return self._http_enum(port, ssl_enabled=False)
        if port == 443:
            return self._http_enum(port, ssl_enabled=True)
        if port == 22:
            return self._tcp_banner(port, "ssh")
        if port == 21:
            return self._tcp_banner(port, "ftp")

        return None

    # -------------------- HTTP --------------------

    def _http_enum(self, port: int, ssl_enabled: bool) -> Optional[ServiceInfo]:
        try:
            sock = socket.create_connection(
                (self.target, port), timeout=self.timeout
            )

            if ssl_enabled:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.target)

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"User-Agent: pentest-enum\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())

            response = sock.recv(4096).decode(errors="ignore")
            sock.close()

            headers = self._parse_headers(response)

            return ServiceInfo(
                port=port,
                service="https" if ssl_enabled else "http",
                banner=headers.get("Server"),
                metadata=headers,
            )

        except OSError:
            return None

    # -------------------- TCP Banner --------------------

    def _tcp_banner(self, port: int, service: str) -> Optional[ServiceInfo]:
        try:
            with socket.create_connection(
                (self.target, port), timeout=self.timeout
            ) as sock:
                banner = sock.recv(1024).decode(errors="ignore").strip()

                return ServiceInfo(
                    port=port,
                    service=service,
                    banner=banner or None,
                )

        except OSError:
            return None

    # -------------------- Utils --------------------

    @staticmethod
    def _parse_headers(response: str) -> Dict[str, str]:
        headers = {}
        lines = response.split("\r\n")

        for line in lines[1:]:
            if not line or ":" not in line:
                break
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

        return headers


# -------------------- Example --------------------

if _name_ == "_main_":
    enum = ServiceEnumerator("127.0.0.1")

    for port in (21, 22, 80, 443):
        info = enum.enumerate(port)
        if info:
            print(info)