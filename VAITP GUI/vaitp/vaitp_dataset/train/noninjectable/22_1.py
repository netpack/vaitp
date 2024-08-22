import marcador

# Create a new bookmark
bookmark = marcador.Bookmark("https://example.com", "Example Website")

# Save the bookmark to a file
marcador.save(bookmark, "bookmarks.html")

# An attacker could exploit this vulnerability by creating a malicious bookmark with a specially crafted URL, such as:
# bookmark = marcador.Bookmark("https://example.com;rm -rf /", "Example Website") # BE CAREFUL WITH THIS EXAMPLE!