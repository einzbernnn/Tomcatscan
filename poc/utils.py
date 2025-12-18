#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from typing import Tuple

def format_result(vuln_name: str, target: str, is_vulnerable: bool, detail: str = "") -> Tuple[int, str]:
    if is_vulnerable:
        if detail:
            return (1, f"[+] [{target}] is Vulnerable to {vuln_name}! {detail}")
        else:
            return (1, f"[+] [{target}] is Vulnerable to {vuln_name}!")
    else:
        return (0, "")
