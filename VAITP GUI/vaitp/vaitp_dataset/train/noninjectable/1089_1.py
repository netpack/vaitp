import dash
from dash import html, dcc

app = dash.Dash(__name__)

# This example demonstrates the vulnerability by allowing user input to be directly rendered in the href attribute
@app.callback(
    dash.dependencies.Output('output', 'children'),
    [dash.dependencies.Input('input', 'value')]
)
def update_output(value):
    # Directly using user input in the href without sanitization
    return html.A('Click here', href=value)

app.layout = html.Div([
    dcc.Input(id='input', type='text', placeholder='Enter URL'),
    html.Div(id='output')
])

if __name__ == '__main__':
    app.run_server(debug=True)