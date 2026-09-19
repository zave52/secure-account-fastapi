import base64
import io

import pyotp
import qrcode


def qr_code_for_secret(secret: str, email: str) -> str:
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="Secure Account")
    image = qrcode.make(uri)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(output.getvalue()).decode()}"


def create_totp(email: str) -> tuple[str, str]:
    secret = pyotp.random_base32()
    return secret, qr_code_for_secret(secret, email)


def valid_code(secret: str | None, code: str | None) -> bool:
    return bool(secret and code and pyotp.TOTP(secret).verify(code, valid_window=1))
