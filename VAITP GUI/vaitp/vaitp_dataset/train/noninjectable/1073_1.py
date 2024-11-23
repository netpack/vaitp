from sklearn.feature_extraction.text import TfidfVectorizer

# Example data that includes sensitive information
documents = [
    "This is a document with a password: secret123",
    "Another document with sensitive info: api_key=xyz"
]

# Create a TfidfVectorizer with stop words
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(documents)

# Access the stop_words_ attribute which may leak sensitive information
print("Stop words attribute (vulnerable):", vectorizer.stop_words_)