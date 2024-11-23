from flask import Flask, request

app = Flask(__name__)

# Simulated function to render wiki content
def render_wiki_content(wiki_code):
    # This is a dangerous operation; it executes arbitrary code
    exec(wiki_code)  # Vulnerable to code injection

@app.route('/execute', methods=['GET'])
def execute_code():
    user_input = request.args.get('code')  # Code injected via URL parameter
    if user_has_view_access():  # Assume this function checks user permissions
        render_wiki_content(user_input)  # Potentially dangerous execution
        return "Code executed!"
    else:
        return "Access denied!", 403

def user_has_view_access():
    # Simulated permission check (always returns True for demonstration)
    return True

if __name__ == '__main__':
    app.run(debug=True)