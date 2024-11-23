import nltk

# Example of vulnerable usage of sent_tokenize and word_tokenize
text_input = "A" * 1000000  # A long input that can trigger ReDoS

# This will take a significant amount of time to process
sentences = nltk.tokenize.sent_tokenize(text_input)
words = nltk.tokenize.word_tokenize(text_input)

print(sentences)
print(words)