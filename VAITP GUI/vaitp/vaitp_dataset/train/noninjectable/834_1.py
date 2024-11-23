from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        user_input = request.form['user_input']
        # Vulnerable to XSS: directly inserting user input into the response
        return f"Password reset link has been sent to {user_input}"
    
    return render_template_string('''
        <form method="post">
            <label for="user_input">Enter your email:</label>
            <input type="text" id="user_input" name="user_input">
            <input type="submit" value="Reset Password">
        </form>
    ''')

if __name__ == '__main__':
    app.run()