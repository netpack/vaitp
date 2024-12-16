# Fixed code (ReportLab 3.5.31 and later)
def start_unichar(self, attrs):
    code = attrs['code']
    try:
        code_point = int(code)
        if code_point < 0 or code_point > 0x10ffff:
            raise ValueError("Invalid Unicode code point")
        unichr(code_point)  # safe execution
    except ValueError as e:
        raise ValueError(f"Invalid Unicode code point: {e}")