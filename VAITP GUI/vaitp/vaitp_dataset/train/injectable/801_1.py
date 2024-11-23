from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/set_theme', methods=['POST'])
def set_theme():
    new_theme_name = request.form.get('newThemeName')
    
    # Validate the new_theme_name to prevent injection
    if not is_valid_theme_name(new_theme_name):
        abort(400, "Invalid theme name")

    # Proceed with setting the theme
    # ...

def is_valid_theme_name(theme_name):
    # Only allow specific theme names or sanitize input
    allowed_themes = ['default', 'dark', 'light']  # Example allowed themes
    return theme_name in allowed_themes

if __name__ == '__main__':
    app.run()