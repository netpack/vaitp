def op_user(user, channel):
    # Vulnerable code: does not check if the user is authorized
    channel.op(user)  # Malicious users can op themselves or others

def voice_user(user, channel):
    # Vulnerable code: does not check if the user is authorized
    channel.voice(user)  # Malicious users can voice themselves or others