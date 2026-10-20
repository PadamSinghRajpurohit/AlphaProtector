from app import validate_email

tests = [
    "not-an-email",
    "test@fakexyz123abc.com",
    "test@gmail.com",
]

for email in tests:
    ok, msg = validate_email(email)
    status = "PASS" if ok else "FAIL"
    # strip emoji for Windows terminal compatibility
    safe_msg = msg.encode("ascii", "ignore").decode()
    print(f"[{status}] {email}")
    print(f"       {safe_msg}")
    print()
