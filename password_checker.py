import re
import getpass
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, NamedTuple

# --- Types ---

class Check(NamedTuple):
    test: Callable[[str], bool]
    tip: str

class Strength(Enum):
    STRONG = "STRONG 💪"
    MEDIUM = "MEDIUM ⚠️"
    WEAK   = "WEAK ❌"

# --- Compiled patterns (once at import, not per call) ---

_RE_UPPER    = re.compile(r"[A-Z]")
_RE_LOWER    = re.compile(r"[a-z]")
_RE_DIGIT    = re.compile(r"\d")
_RE_SPECIAL  = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
_RE_REPEAT   = re.compile(r"(.)\1{2,}")  # 3+ identical chars in a row (e.g. "aaa")

# --- Common password blocklist (O(1) lookup with frozenset) ---

_COMMON: frozenset[str] = frozenset({
    "password", "password1", "password123", "123456", "12345678",
    "qwerty", "qwerty123", "abc123", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "superman", "batman",
})

# --- Checks ---

CHECKS: list[Check] = [
    Check(lambda p: len(p) >= 8,                         "Use at least 8 characters"),
    Check(lambda p: len(p) >= 12,                        "Use 12+ characters for extra strength"),
    Check(lambda p: bool(_RE_UPPER.search(p)),           "Add uppercase letters"),
    Check(lambda p: bool(_RE_LOWER.search(p)),           "Add lowercase letters"),
    Check(lambda p: bool(_RE_DIGIT.search(p)),           "Add numbers"),
    Check(lambda p: bool(_RE_SPECIAL.search(p)),         "Add special characters (!@#$ etc)"),
    Check(lambda p: not bool(_RE_REPEAT.search(p)),      "Avoid repeated characters (e.g. 'aaa')"),
    Check(lambda p: p.lower() not in _COMMON,            "Avoid common passwords"),
]

# --- Result ---

@dataclass
class PasswordResult:
    score: int
    max_score: int
    strength: Strength
    feedback: list[str] = field(default_factory=list)

    @property
    def percentage(self) -> int:
        return int((self.score / self.max_score) * 100)

    def __str__(self) -> str:
        """Lets you print(result) directly — no separate display function needed."""
        lines = [
            f"\nPassword Strength: {self.strength.value} "
            f"({self.score}/{self.max_score} — {self.percentage}%)"
        ]
        if self.feedback:
            lines.append("Suggestions:")
            lines.extend(f"  - {tip}" for tip in self.feedback)
        return "\n".join(lines)

# --- Logic ---

def check_password(password: str, checks: list[Check] = CHECKS) -> PasswordResult:
    """
    Evaluate password strength.
    `checks` is injectable — swap it in tests without touching globals.
    """
    score, feedback = 0, []

    for check in checks:
        if check.test(password):
            score += 1
        else:
            feedback.append(check.tip)

    max_score = len(checks)
    ratio     = score / max_score

    strength = (
        Strength.STRONG if ratio == 1.0  else
        Strength.MEDIUM if ratio >= 0.6  else
        Strength.WEAK
    )

    return PasswordResult(score, max_score, strength, feedback)

# --- Entry point ---

if __name__ == "__main__":
    pw = getpass.getpass("Enter password to check: ")
    print(check_password(pw))
