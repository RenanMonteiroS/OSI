def generateTotpQrCode(email, qrcodeFullPathName):
    from random import SystemRandom
    from base64 import b32encode
    from pyotp import TOTP
    from qrcode import make
    
    from flask import current_app
    from string import ascii_uppercase, digits
    
    mfaSecret = ''.join(SystemRandom().choice(ascii_uppercase + digits) for _ in range(16))
    totp = TOTP(b32encode(str.encode(mfaSecret)))

    img = make(totp.provisioning_uri(name=email, issuer_name=f'{current_app.config['COMPANY_NAME']} OSI'))
    img.save(qrcodeFullPathName)

    return mfaSecret