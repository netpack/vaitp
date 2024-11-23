import nltk

# Function to safely tokenize input with a length limit
def safe_tokenize(text, max_length=1000):
    if len(text) > max_length:
        raise ValueError(f"Input text exceeds the maximum allowed length of {max_length}.")
    return nltk.tokenize.sent_tokenize(text), nltk.tokenize.word_tokenize(text)

# Example usage
try:
    text_input = "Your long input text here..."  # Replace with actual input
    sentences, words = safe_tokenize(text_input)
except ValueError as e:
    print(e)