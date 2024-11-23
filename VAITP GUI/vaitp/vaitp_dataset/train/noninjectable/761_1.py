from flask import Flask, request

app = Flask(__name__)

@app.route('/delete_wiki', methods=['POST'])
def delete_wiki():
    wiki_id = request.args.get('wikiId')

    # Vulnerable code: directly using wiki_id without validation
    # This allows for arbitrary code execution if the wiki_id is crafted maliciously
    exec(f"delete_wiki_logic('{wiki_id}')")  # Placeholder for actual deletion logic

    return 'Wiki deletion initiated.', 200

if __name__ == '__main__':
    app.run()