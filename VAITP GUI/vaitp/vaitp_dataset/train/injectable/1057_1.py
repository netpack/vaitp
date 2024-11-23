import nltk
import ssl

# To prevent downloading untrusted pickled data, we can enforce SSL verification
ssl._create_default_https_context = ssl._create_unverified_context

# Example of downloading a trusted NLTK resource
nltk.download('punkt', ssl=True)  # Ensure SSL is used for secure downloads