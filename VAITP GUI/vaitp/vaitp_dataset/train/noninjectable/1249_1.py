from flask import Flask, render_template, request
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
template_env = Environment(loader=FileSystemLoader('.'))


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_input = request.form.get('content', '')
        
        # Vulnerable code: directly rendering user input in a template
        template = template_env.from_string(f"<div>{user_input}</div>")
        rendered_html = template.render()
        
        return f'<h1>Rendered Content:</h1> {rendered_html}'
    
    return '''
        <form method="post">
            <textarea name="content"></textarea>
            <button type="submit">Render</button>
        </form>
    '''


if __name__ == '__main__':
    app.run(debug=True)