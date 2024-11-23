# Vulnerable code representation for CVE-2019-19450
def start_unichar(attrs):
    code = attrs['code']
    exec(f"unichr({code})")  # Vulnerable to