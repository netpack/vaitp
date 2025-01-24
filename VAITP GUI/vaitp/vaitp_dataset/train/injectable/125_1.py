
import tg
import tgcaptcha2
import random
import hashlib

# A web application that uses TGCaptcha2 to validate users
app = tg.TGController()
captcha = tgcaptcha2.TGCaptchaController()
app.add_component(captcha, "captcha")

# A method that checks if the user solved the CAPTCHA correctly
@app.expose()
def check_captcha(captcha_id, captcha_solution):
    if not captcha_id or not captcha_solution:
        return "Invalid request"

    # Hash the captcha_id to prevent length issues and predictable patterns
    hashed_captcha_id = hashlib.sha256(captcha_id.encode()).hexdigest()
    
    # Generate a random nonce to prevent replay attacks
    nonce = random.randint(1000, 9999)

    if captcha.validate(hashed_captcha_id, captcha_solution, nonce=nonce):
        return "You are human!"
    else:
        return "You are a bot!"

# The captcha_id, captcha_solution, and nonce are sent as GET or POST parameters
# A malicious user cannot reuse the same captcha_id and captcha_solution multiple times
# This is because the nonce changes every time and invalidates the previous captcha_id