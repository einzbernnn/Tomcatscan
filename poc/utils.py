#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from typing import Tuple

HTTPS_PORTS = {443, 8443}

def normalize_target(host: str, port: int, scheme: str = None) -> str:
    port = int(port)
    if scheme is None:
        scheme = "https" if port in HTTPS_PORTS else "http"
    return f"{scheme}://{host}:{port}"

def format_result(vuln_name: str, target: str, is_vulnerable: bool, detail: str = "") -> Tuple[int, str]:
    if is_vulnerable:
        if detail:
            return (1, f"[+] [{target}] is Vulnerable to {vuln_name}! {detail}")
        else:
            return (1, f"[+] [{target}] is Vulnerable to {vuln_name}!")
    else:
        if detail:
            return (0, f"[-] [{target}] seems no vuln to {vuln_name}: {detail}")
        else:
            return (0, f"[-] [{target}] seems no vuln to {vuln_name}")


