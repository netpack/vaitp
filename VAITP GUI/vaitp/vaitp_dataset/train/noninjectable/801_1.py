from flask import Flask, request

app = Flask(__name__)

@app.route('/set_theme', methods=['POST'])
def set_theme():
    new_theme_name = request.form.get('newThemeName')
    
    # Vulnerable code: directly using the new_theme_name without validation
    # This allows for arbitrary code execution via script macros
    execute_theme_change(new_theme_name)

def execute_theme_change(theme_name):
    # Simulated execution of theme change, which could include arbitrary code execution
    eval(theme_name)  # Dangerous: allows execution of arbitrary code

if __name__ == '__main__':
    app.run()