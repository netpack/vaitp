from flask import Flask, render_template

app = Flask(__name__)

@app.route('/dashboard')
def dashboard():
    # Render the dashboard without checking if the user is authenticated
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)