from flask import Flask, request, abort
import re

app = Flask(__name__)

# Function to validate the wikiId parameter
def is_valid_wiki_id(wiki_id):
    # Only allow alphanumeric characters and underscores
    return re.match(r'^[a-zA-Z0-9_]+$', wiki_id) is not None

@app.route('/delete_wiki', methods=['POST'])
def delete_wiki():
    wiki_id = request.args.get('wikiId')
    
    # Validate the wikiId parameter
    if not wiki_id or not is_valid_wiki_id(wiki_id):
        abort(400, 'Invalid wikiId parameter.')

    # Proceed with the deletion logic if valid
    # delete_wiki_logic(wiki_id)  # Placeholder for actual deletion logic

    return 'Wiki deleted successfully.', 200

if __name__ == '__main__':
    app.run()