import re
from dataclasses import dataclass, field

# --- Data ---

@dataclass
class PasswordResult:
    score: int
    max_score: int
    strength: str
    feedback: list[str] = field(default_factory=list)

    @property
    def percentage(self) -> int:
        return int((self.score / self.max_score) * 100)


# Each check is a (test_function, failure_tip) pair.
# Adding a new rule = adding one line here, nothing else changes.
CHECKS: list[tuple] = [
    (lambda p: len(p) >= 8,                                    "Use at least 8 characters"),
    (lambda p: len(p) >= 12,                                   "Use 12+ characters for extra strength"),
    (lambda p: bool(re.search(r"[A-Z]", p)),                   "Add uppercase letters"),
    (lambda p: bool(re.search(r"[a-z]", p)),                   "Add lowercase letters"),
    (lambda p: bool(re.search(r"\d", p)),                      "Add numbers"),
    (lambda p: bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", p)), "Add special characters (!@#$ etc)"),
]

# --- Logic ---

def check_password(password: str) -> PasswordResult:
    """Evaluate password strength and return a structured result."""
    score, feedback = 0, []

    for passes, tip in CHECKS:
        if passes(password):
            score += 1
        else:
            feedback.append(tip)

    max_score = len(CHECKS)
    ratio = score / max_score

    if ratio == 1.0:
        strength = "STRONG 💪"
    elif ratio >= 0.6:
        strength = "MEDIUM ⚠️"
    else:
        strength = "WEAK ❌"

    return PasswordResult(score, max_score, strength, feedback)

# --- Display ---

def display_result(result: PasswordResult) -> None:
    """Print a password result to stdout."""
    print(f"\nPassword Strength: {result.strength} ({result.score}/{result.max_score} — {result.percentage}%)")
    if result.feedback:
        print("Suggestions:")
        for tip in result.feedback:
            print(f"  - {tip}")

# --- Entry point ---

if __name__ == "__main__":
    import getpass
    password = getpass.getpass("Enter password to check: ")  # hides input while typing
    display_result(check_password(password))
