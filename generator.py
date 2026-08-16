"""
generator.py
Cryptographically secure random password generation using `secrets`
(never use `random` for anything security-related).
"""

import secrets
import string


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if length < 4:
        raise ValueError("Length must be at least 4 to guarantee character diversity.")

    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?")

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    # Guarantee at least one character from each selected pool.
    password_chars = [secrets.choice(pool) for pool in pools]

    all_chars = "".join(pools)
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(all_chars) for _ in range(remaining)]

    # Shuffle securely so the guaranteed chars aren't always at the front.
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)

  print("hell")