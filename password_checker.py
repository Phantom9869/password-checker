import re

def check_password(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add numbers")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters (!@#$ etc)")

    if score == 5:
        strength = "STRONG 💪"
    elif score >= 3:
        strength = "MEDIUM ⚠️"
    else:
        strength = "WEAK ❌"

    print(f"\nPassword Strength: {strength} ({score}/5)")
    if feedback:
        print("Suggestions:")
        for f in feedback:
            print(f"  - {f}")

if __name__ == "__main__":
    password = input("Enter password to check: ")
    check_password(password)
