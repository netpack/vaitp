import dash
from dash import html, dcc
import urllib.parse

app = dash.Dash(__name__)

def sanitize_url(url):
    # Basic sanitation to prevent XSS
    return urllib.parse.quote(url, safe=':/')

@app.callback(
    dash.dependencies.Output('output', 'children'),
    [dash.dependencies.Input('input', 'value')]
)
def update_output(value):
    safe_value = sanitize_url(value)
    return html.A('Click here', href=safe_value)

app.layout = html.Div([
    dcc.Input(id='input', type='text', placeholder='Enter URL'),
    html.Div(id='output')
])

if __name__ == '__main__':
    app.run_server(debug=True)