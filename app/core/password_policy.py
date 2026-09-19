import re

WEAK_PASSWORDS = {
    "password", "password123", "admin", "admin123", "qwerty",
    "qwerty123", "letmein", "12345678", "welcome",
}


def validate_password(password: str) -> list[str]:
    """Return validation messages; an empty list means valid."""
    errors: list[str] = []
    if len(password) < 8:
        errors.append("Password must contain at least 8 characters.")
    if password.casefold() in WEAK_PASSWORDS:
        errors.append("This password is common and unsafe. Choose another one.")
    if not re.search(r"[A-Z]", password):
        errors.append("Add an uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Add a lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Add a digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Add a special character.")
    return errors
