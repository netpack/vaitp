from flask import Flask, request
import re

app = Flask(__name__)

def delete_wiki_logic(wiki_id):
    # Placeholder for actual deletion logic
    print(f"Deleting wiki with id: {wiki_id}")
    pass


@app.route('/delete_wiki', methods=['POST'])
def delete_wiki():
    wiki_id = request.args.get('wikiId')

    if not wiki_id:
      return "Missing wikiId parameter", 400
    
    if not re.match(r"^[a-zA-Z0-9_-]+$", wiki_id):
        return "Invalid wikiId format", 400


    delete_wiki_logic(wiki_id)

    return 'Wiki deletion initiated.', 200

if __name__ == '__main__':
    app.run(debug=True)