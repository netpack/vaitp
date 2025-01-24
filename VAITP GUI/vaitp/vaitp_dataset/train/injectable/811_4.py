import re
from flask import Flask, request, render_template, session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap5

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
bootstrap = Bootstrap5(app)

class ThemeForm(FlaskForm):
    newThemeName = StringField('New Theme Name', validators=[DataRequired()])
    submit = SubmitField('Create')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = ThemeForm()
    message = None
    themes = []

    if request.method == 'POST' and form.validate_on_submit():
        if 'form_token' in request.form and session.get('form_token') == request.form['form_token']:
            new_theme_name = form.newThemeName.data
            if not re.match(r'^[a-zA-Z0-9\s_.-]+$', new_theme_name):
                message = f"platform.flamingo.themes.home.create.csrf [{new_theme_name}]"
            else:
                 themes.append({'title': f'Title of {new_theme_name} theme', 
                    'style': 'background-color: lightblue;',
                    'link': 'space/' + new_theme_name}) 
                 message = f"Theme {new_theme_name} created successfully!"
        else:
            message = f"Invalid Form Token"

    session['form_token'] = str(hash(app.secret_key + str(form.newThemeName.data)))
    return render_template('index.html', form=form, message=message, themes=themes, form_token=session['form_token'])

@app.template_filter('safe_html')
def safe_html_filter(value):
    allowed_tags = ['a', 'b', 'i', 'em', 'strong', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'span', 'div']
    allowed_attributes = ['href', 'class', 'id', 'style']
    
    def sanitize_html(html):
        clean_html = ""
        for part in re.split(r'(<[^>]*>)', html):
           if part.startswith("<") and part.endswith(">"):
                tag_match = re.match(r'<(/)?([a-zA-Z]+)([^>]*)>', part)
                if tag_match:
                   is_closing_tag = tag_match.group(1)
                   tag_name = tag_match.group(2).lower()
                   tag_attributes = tag_match.group(3)
                   if tag_name in allowed_tags:
                       clean_attributes = ""
                       for attr_match in re.finditer(r'([a-zA-Z]+)="([^"]*)"', tag_attributes):
                            attr_name = attr_match.group(1).lower()
                            attr_value = attr_match.group(2)

                            if attr_name in allowed_attributes:
                                clean_attributes += f' {attr_name}="{attr_value}"'

                       clean_html += f"<{is_closing_tag or ''}{tag_name}{clean_attributes}>"
                   else:
                       clean_html += ""
                else:
                    clean_html += ""
           else:
               clean_html += re.sub(r'<', '&lt;', part)

        return clean_html
    
    return sanitize_html(str(value))

if __name__ == '__main__':
    app.run(debug=True)