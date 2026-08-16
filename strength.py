"""
strength.py
Password strength analysis: entropy calculation, pattern/weakness detection,
and common-password lookup.
"""

import math
import re

# Small embedded sample of extremely common passwords.
# In a real deployment you'd load the full rockyou.txt or similar list from disk.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "iloveyou", "dragon", "master", "sunshine",
    "football", "shadow", "superman", "trustno1", "qwerty123",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def _char_pool_size(password: str) -> int:
    """Estimate the size of the character pool used, for entropy math."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # rough estimate of common symbol set
    return pool or 1


def calculate_entropy(password: str) -> float:
    """Shannon-style entropy estimate in bits: log2(pool_size) * length."""
    pool = _char_pool_size(password)
    return round(len(password) * math.log2(pool), 2)


def has_sequential_chars(password: str, run_length: int = 4) -> bool:
    """Detect ascending/descending sequences like 'abcd' or '4321'."""
    lower = password.lower()
    for i in range(len(lower) - run_length + 1):
        chunk = lower[i:i + run_length]
        codes = [ord(c) for c in chunk]
        ascending = all(codes[j + 1] - codes[j] == 1 for j in range(len(codes) - 1))
        descending = all(codes[j] - codes[j + 1] == 1 for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def has_keyboard_walk(password: str, run_length: int = 4) -> bool:
    """Detect keyboard-adjacent sequences like 'qwerty' or 'asdf'."""
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            if row[i:i + run_length] in lower:
                return True
    return False


def has_repeated_chars(password: str, run_length: int = 4) -> bool:
    """Detect long runs of the same character, e.g. 'aaaa'."""
    return bool(re.search(r"(.)\1{" + str(run_length - 1) + r",}", password))


def analyze_password(password: str) -> dict:
    """
    Run a full analysis and return a report dict:
    {score (0-100), rating, entropy_bits, issues: [...], suggestions: [...]}
    """
    issues = []
    suggestions = []

    length = len(password)
    entropy = calculate_entropy(password)

    if length < 8:
        issues.append("Too short (under 8 characters)")
        suggestions.append("Use at least 12 characters")
    elif length < 12:
        suggestions.append("Consider 12+ characters for stronger protection")

    if password.lower() in COMMON_PASSWORDS:
        issues.append("Found in common password list")
        suggestions.append("Avoid well-known passwords entirely")

    if not re.search(r"[a-z]", password):
        issues.append("No lowercase letters")
    if not re.search(r"[A-Z]", password):
        issues.append("No uppercase letters")
    if not re.search(r"[0-9]", password):
        issues.append("No digits")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("No special characters")
        suggestions.append("Add symbols like !@#$%^&*")

    if has_sequential_chars(password):
        issues.append("Contains sequential characters (e.g. abcd, 4321)")
    if has_keyboard_walk(password):
        issues.append("Contains a keyboard pattern (e.g. qwerty, asdf)")
    if has_repeated_chars(password):
        issues.append("Contains repeated character runs (e.g. aaaa)")

    # Scoring: blend entropy with a penalty per issue found.
    score = min(100, entropy)  # entropy of ~60+ bits already caps near 100
    score -= len(issues) * 10
    score = max(0, min(100, round(score)))

    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 5)  # common passwords are always critically weak

    if score >= 80:
        rating = "Strong"
    elif score >= 60:
        rating = "Moderate"
    elif score >= 35:
        rating = "Weak"
    else:
        rating = "Very Weak"

    return {
        "length": length,
        "entropy_bits": entropy,
        "score": score,
        "rating": rating,
        "issues": issues,
        "suggestions": suggestions,
    }


def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
    """
    Rough offline brute-force crack time estimate assuming an attacker
    can attempt `guesses_per_second` guesses (1e10 ~ modern GPU rig).
    """
    combinations = 2 ** entropy_bits
    seconds = combinations / (2 * guesses_per_second)  # average case = half the space

    units = [
        ("seconds", 60), ("minutes", 60), ("hours", 24),
        ("days", 365), ("years", 100), ("centuries", float("inf")),
    ]
    value = seconds
    for name, factor in units:
        if value < factor:
            return f"~{value:,.1f} {name}"
        value /= factor
    return "an astronomically long time"
