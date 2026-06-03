#!/usr/bin/env python3
"""
Features:
- Cryptographically secure (secrets)
- Configurable password policy
- Entropy estimation
- Optional exclusion of ambiguous characters
- CLI-ready
"""

from _future_ import annotations

import argparse
import math
import secrets
import string
from dataclasses import dataclass
from typing import Iterable


# -------------------- Policy --------------------

@dataclass(frozen=True)
class PasswordPolicy:
    length: int = 16
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True  # e.g. 0,O,1,l,I
    min_each_group: int = 1          # ensure complexity


AMBIGUOUS = set("0O1lI")


# -------------------- Core --------------------

class PasswordGenerator:
    def _init_(self, policy: PasswordPolicy):
        self.policy = policy
        self._validate_policy()
        self.charsets = self._build_charsets()
        self.alphabet = "".join(self.charsets)

    def _validate_policy(self) -> None:
        if self.policy.length < 8:
            raise ValueError("Password length must be >= 8")
        if not any([
            self.policy.use_lower,
            self.policy.use_upper,
            self.policy.use_digits,
            self.policy.use_symbols,
        ]):
            raise ValueError("At least one character group must be enabled")

        enabled_groups = sum([
            self.policy.use_lower,
            self.policy.use_upper,
            self.policy.use_digits,
            self.policy.use_symbols,
        ])
        if self.policy.min_each_group * enabled_groups > self.policy.length:
            raise ValueError("Length too small for required group minimums")

    def _filter(self, chars: Iterable[str]) -> str:
        if not self.policy.exclude_ambiguous:
            return "".join(chars)
        return "".join(c for c in chars if c not in AMBIGUOUS)

    def _build_charsets(self) -> list[str]:
        sets = []
        if self.policy.use_lower:
            sets.append(self._filter(string.ascii_lowercase))
        if self.policy.use_upper:
            sets.append(self._filter(string.ascii_uppercase))
        if self.policy.use_digits:
            sets.append(self._filter(string.digits))
        if self.policy.use_symbols:
            sets.append(self.filter("!@#$%^&*()-=+[]{};:,.<>?/"))
        return sets

    def generate(self) -> str:
        # 1. Guarantee minimum from each group
        password_chars = [
            secrets.choice(charset)
            for charset in self.charsets
            for _ in range(self.policy.min_each_group)
        ]

        # 2. Fill the rest from full alphabet
        remaining = self.policy.length - len(password_chars)
        password_chars.extend(
            secrets.choice(self.alphabet) for _ in range(remaining)
        )

        # 3. Shuffle securely
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)

    def entropy_bits(self) -> float:
        return math.log2(len(self.alphabet) ** self.policy.length)


# -------------------- CLI --------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Password Generator")
    parser.add_argument("-l", "--length", type=int, default=16)
    parser.add_argument("--no-lower", action="store_true")
    parser.add_argument("--no-upper", action="store_true")
    parser.add_argument("--no-digits", action="store_true")
    parser.add_argument("--no-symbols", action="store_true")
    parser.add_argument("--allow-ambiguous", action="store_true")

    args = parser.parse_args()

    policy = PasswordPolicy(
        length=args.length,
        use_lower=not args.no_lower,
        use_upper=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
        exclude_ambiguous=not args.allow_ambiguous,
    )

    gen = PasswordGenerator(policy)
    password = gen.generate()

    print(password)
    print(f"Entropy: {gen.entropy_bits():.2f} bits")


if _name_ == "_main_":
    main()