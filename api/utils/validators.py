import re

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'

def validate_email(email):
    return bool(re.match(EMAIL_REGEX, email))


def validate_password(password):
    if not password:
        return False

    # strong password rules
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False

    return True


def validate_string_length(value, min_len=1, max_len=255):
    if not isinstance(value, str):
        return False
    return min_len <= len(value) <= max_len


def sanitize_input(text):
    if not text:
        return text
    return re.sub(r'[<>\"\'%;()&+]', '', text)