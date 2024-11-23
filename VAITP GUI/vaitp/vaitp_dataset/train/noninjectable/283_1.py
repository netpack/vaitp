# Vulnerable code that uses the potentially malicious democritus-urls package
import democritus_urls

def fetch_data():
    # This function may call a method from the democritus_urls package
    data = democritus_urls.get_data()
    print("Fetched data:", data)

if __name__ == "__main__":
    fetch_data()