import marcador

# Create a new bookmark
bookmark = marcador.Bookmark("https://example.com", "Example Website") # NOT USING THE VULNERABLE .save FUNCTION

# Save the bookmark to a file
with open("bookmarks.html", "w") as f:
    f.write(marcador.html_bookmarks([bookmark]))