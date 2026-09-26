import re
import math
import hashlib
import getpass
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, NamedTuple

# --- Types ---

class Check(NamedTuple):
    test:   Callable[[str], bool]
    tip:    str
    weight: float = 1.0   # NEW: checks contribute differently to the score

class Strength(Enum):          # NEW: four tiers instead of three
    VERY_WEAK = "VERY WEAK 🚨"
    WEAK      = "WEAK ❌"
    MEDIUM    = "MEDIUM ⚠️"
    STRONG    = "STRONG 💪"

# --- Compiled patterns ---

_RE_UPPER   = re.compile(r"[A-Z]")
_RE_LOWER   = re.compile(r"[a-z]")
_RE_DIGIT   = re.compile(r"\d")
_RE_SPECIAL = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
_RE_REPEAT  = re.compile(r"(.)\1{2,}")   # 3+ identical chars in a row

# --- NEW: Keyboard / sequential pattern detection ---

_SEQ_PATTERNS = (
    "abcdefghijklmnopqrstuvwxyz",   # alphabetical run
    "qwertyuiopasdfghjklzxcvbnm",   # QWERTY keyboard rows
    "0123456789",                    # digit run
)

def _has_sequence(password: str, min_len: int = 3) -> bool:
    """True if the password contains a sequential or keyboard run (forward or reversed)."""
    p = password.lower()
    for seq in _SEQ_PATTERNS:
        for i in range(len(seq) - min_len + 1):
            chunk = seq[i : i + min_len]
            if chunk in p or chunk[::-1] in p:   # catches "cba", "321" too
                return True
    return False

# --- Common password blocklist ---

_COMMON: frozenset[str] = frozenset({
    "password", "password1", "password123", "123456", "12345678",
    "qwerty", "qwerty123", "abc123", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "superman", "batman",
})

# --- NEW: Entropy & crack-time estimation ---

_GUESSES_PER_SEC = 10_000_000_000   # 10 B/s: modern GPU, offline attack

def _entropy_bits(password: str) -> float:
    """Estimate entropy (bits) from the character classes actually used."""
    pool = 0
    if _RE_LOWER.search(password):   pool += 26
    if _RE_UPPER.search(password):   pool += 26
    if _RE_DIGIT.search(password):   pool += 10
    if _RE_SPECIAL.search(password): pool += 32
    return len(password) * math.log2(pool) if pool else 0.0

def _crack_label(entropy: float) -> str:
    """Translate entropy (bits) to a human-readable offline crack-time."""
    secs = (2.0 ** entropy) / _GUESSES_PER_SEC / 2.0  # /2 = average case

    thresholds = [
        (1,            "instantly"),
        (60,           f"{secs:.0f} second(s)"),
        (3_600,        f"{secs/60:.0f} minute(s)"),
        (86_400,       f"{secs/3_600:.0f} hour(s)"),
        (31_536_000,   f"{secs/86_400:.0f} day(s)"),
        (3_153_600_000, f"{secs/31_536_000:.0f} year(s)"),
    ]
    for limit, label in thresholds:
        if secs < limit:
            return label
    return "centuries"

# --- NEW: Configurable policy ---

@dataclass
class PasswordPolicy:
    """
    All tuneable thresholds in one place.
    Swap in a custom policy without touching CHECKS.
    """
    strong_ratio: float = 0.85   # weighted ratio needed for STRONG
    medium_ratio: float = 0.55   # weighted ratio needed for MEDIUM

DEFAULT_POLICY = PasswordPolicy()

# --- Weighted checks (3 length tiers, 2 negative-pattern checks) ---

CHECKS: list[Check] = [
    # Length has the biggest effect on entropy — weight 2×
    Check(lambda p: len(p) >= 8,                     "Use at least 8 characters",            weight=2.0),
    Check(lambda p: len(p) >= 12,                    "Use 12+ characters for extra strength", weight=2.0),
    Check(lambda p: len(p) >= 16,                    "16+ chars is near-uncrackable",         weight=1.0),
    # Standard complexity — weight 1×
    Check(lambda p: bool(_RE_UPPER.search(p)),       "Add uppercase letters"),
    Check(lambda p: bool(_RE_LOWER.search(p)),       "Add lowercase letters"),
    Check(lambda p: bool(_RE_DIGIT.search(p)),       "Add numbers"),
    Check(lambda p: bool(_RE_SPECIAL.search(p)),     "Add special characters (!@#$ etc)"),
    # Negative patterns — weight 1.5× (failing these hurts more than simple rule misses)
    Check(lambda p: not _RE_REPEAT.search(p),        "Avoid repeated characters (e.g. 'aaa')",          weight=1.5),
    Check(lambda p: not _has_sequence(p),            "Avoid sequences (e.g. 'abc', '123', 'qwerty')",   weight=1.5),
    Check(lambda p: p.lower() not in _COMMON,        "Avoid common passwords",                           weight=1.5),
]

# --- Result ---

@dataclass
class PasswordResult:
    score:     float       # weighted points earned
    max_score: float       # total possible weighted points
    entropy:   float       # bits
    strength:  Strength
    feedback:  list[str] = field(default_factory=list)
    reused:    bool = False   # NEW: flagged by PasswordChecker

    @property
    def percentage(self) -> int:
        return int((self.score / self.max_score) * 100) if self.max_score else 0

    @property
    def crack_time(self) -> str:
        return _crack_label(self.entropy)

    def __str__(self) -> str:
        lines = [
            f"\nStrength    : {self.strength.value}",
            f"Score       : {self.percentage}%  ({self.score:.1f} / {self.max_score:.1f} weighted pts)",
            f"Entropy     : {self.entropy:.1f} bits",
            f"Crack time  : {self.crack_time}  (offline GPU attack)",
        ]
        if self.reused:
            lines.append("⚠️  Already used in this session — choose a different password")
        if self.feedback:
            lines.append("\nSuggestions:")
            lines.extend(f"  - {tip}" for tip in self.feedback)
        return "\n".join(lines)

# --- Core logic ---

def check_password(
    password: str,
    checks: list[Check]    = CHECKS,
    policy: PasswordPolicy = DEFAULT_POLICY,
) -> PasswordResult:
    """
    Evaluate password strength with weighted checks and entropy estimation.

    Args:
        password: Password to evaluate.
        checks:   Rule list — injectable for testing or custom policies.
        policy:   Strength-classification thresholds.
    """
    score, max_score, feedback = 0.0, 0.0, []

    for check in checks:
        max_score += check.weight
        if check.test(password):
            score += check.weight
        else:
            feedback.append(check.tip)

    ratio    = score / max_score if max_score else 0.0
    entropy  = _entropy_bits(password)

    strength = (
        Strength.STRONG    if ratio >= policy.strong_ratio else
        Strength.MEDIUM    if ratio >= policy.medium_ratio else
        Strength.WEAK      if score  > 0                  else
        Strength.VERY_WEAK
    )

    return PasswordResult(score, max_score, entropy, strength, feedback)

# --- NEW: Stateful session checker ---

class PasswordChecker:
    """
    Stateful wrapper that detects password reuse across a session.
    Stores SHA-256 digests — never plaintext.
    """

    def __init__(
        self,
        checks: list[Check]    = CHECKS,
        policy: PasswordPolicy = DEFAULT_POLICY,
    ) -> None:
        self._checks  = checks
        self._policy  = policy
        self._history: set[str] = set()

    def check(self, password: str) -> PasswordResult:
        digest = hashlib.sha256(password.encode()).hexdigest()
        result = check_password(password, self._checks, self._policy)
        result.reused = digest in self._history
        self._history.add(digest)
        return result

    def clear_history(self) -> None:
        self._history.clear()

# --- Entry point: interactive loop ---

if __name__ == "__main__":
    checker = PasswordChecker()
    print("Password Strength Checker  (Ctrl-C to quit)\n")
    while True:
        try:
            pw = getpass.getpass("Enter password: ").strip()
            if not pw:
                continue
            print(checker.check(pw), "\n")
        except KeyboardInterrupt:
            print("\nBye!")
            break
