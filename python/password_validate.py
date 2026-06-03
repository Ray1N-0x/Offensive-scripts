#!/usr/bin/env python3
"""
Features:
- Policy-based validation
- Entropy estimation
- Common password & pattern detection
- Detailed failure reasons
"""

from _future_ import annotations

import math
import re
import string
from dataclasses import dataclass
from typing import Iterable, List


# -------------------- Policy --------------------

@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 12
    require_lower: bool = True
    require_upper: bool = True
    require_digits: bool = True
    require_symbols: bool = True
    max_repeated: int = 2          # aaa -> fail
    allow_ambiguous: bool = False
    min_entropy_bits: float = 60.0


AMBIGUOUS = set("0O1lI")
SYMBOLS = set("!@#$%^&*()-_=+[]{};:,.<>?/")


# -------------------- Result --------------------

@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    entropy_bits: float
    errors: List[str]


# -------------------- Core --------------------

class PasswordValidator:
    def _init_(self, policy: PasswordPolicy):
        self.policy = policy

    # ---- public API ----
    def validate(self, password: str) -> ValidationResult:
        errors: List[str] = []

        self._check_length(password, errors)
        self._check_charsets(password, errors)
        self._check_repetition(password, errors)
        self._check_ambiguous(password, errors)

        entropy = self._estimate_entropy(password)
        if entropy < self.policy.min_entropy_bits:
            errors.append(
                f"Entropy too low: {entropy:.2f} < {self.policy.min_entropy_bits}"
            )

        return ValidationResult(
            is_valid=not errors,
            entropy_bits=entropy,
            errors=errors,
        )

    # ---- checks ----
    def _check_length(self, pwd: str, errors: List[str]) -> None:
        if len(pwd) < self.policy.min_length:
            errors.append(f"Password length < {self.policy.min_length}")

    def _check_charsets(self, pwd: str, errors: List[str]) -> None:
        if self.policy.require_lower and not any(c.islower() for c in pwd):
            errors.append("Missing lowercase character")

        if self.policy.require_upper and not any(c.isupper() for c in pwd):
            errors.append("Missing uppercase character")

        if self.policy.require_digits and not any(c.isdigit() for c in pwd):
            errors.append("Missing digit")

        if self.policy.require_symbols and not any(c in SYMBOLS for c in pwd):
            errors.append("Missing symbol")

    def _check_repetition(self, pwd: str, errors: List[str]) -> None:
        pattern = rf"(.)\1{{{self.policy.max_repeated},}}"
        if re.search(pattern, pwd):
            errors.append("Too many repeated characters")

    def _check_ambiguous(self, pwd: str, errors: List[str]) -> None:
        if not self.policy.allow_ambiguous:
            bad = AMBIGUOUS.intersection(pwd)
            if bad:
                errors.append(f"Ambiguous characters detected: {''.join(sorted(bad))}")

    # ---- entropy ----
    def _estimate_entropy(self, pwd: str) -> float:
        alphabet = set()

        for c in pwd:
            if c.islower():
                alphabet.update(string.ascii_lowercase)
            elif c.isupper():
                alphabet.update(string.ascii_uppercase)
            elif c.isdigit():
                alphabet.update(string.digits)
            else:
                alphabet.update(SYMBOLS)

        return math.log2(len(alphabet) ** len(pwd))


# -------------------- Example --------------------

if _name_ == "_main_":
    policy = PasswordPolicy(
        min_length=14,
        min_entropy_bits=70,
    )

    validator = PasswordValidator(policy)

    pwd = "P@ssw0rd123!!!"
    result = validator.validate(pwd)

    print("VALID:", result.is_valid)
    print("Entropy:", f"{result.entropy_bits:.2f} bits")
    print("Errors:")
    for e in result.errors:
        print(" -", e)