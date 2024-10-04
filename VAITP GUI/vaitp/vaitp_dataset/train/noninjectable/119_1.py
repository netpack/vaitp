# This code assumes that Python 3.6.4 or lower is installed
import wave

# The attacker can create a malicious wav file with a zero channel value
# and trick the victim to open it with the wave module
malicious_wav = "zero_channel.wav"

# This will raise a ZeroDivisionError and cause a denial of service
wav_file = wave.open(malicious_wav, "rb")