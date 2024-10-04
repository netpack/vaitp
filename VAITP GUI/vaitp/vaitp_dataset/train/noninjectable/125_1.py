import tg
import tgcaptcha2
# A web application that uses TGCaptcha2 to validate users
app = tg.TGController()
captcha = tgcaptcha2.TGCaptchaController()
app.add_component(captcha, "captcha")
# A method that checks if the user solved the CAPTCHA correctly
@app.expose()
def check_captcha(self, captcha_id, captcha_solution):
    if captcha.validate(captcha_id, captcha_solution):
        return "You are human!"
    else:
        return "You are a bot!"
# The captcha_id and captcha_solution are sent as GET or POST parameters
# A malicious user could reuse the same captcha_id and captcha_solution multiple times
# This would bypass the CAPTCHA protection and allow the user to access the web application