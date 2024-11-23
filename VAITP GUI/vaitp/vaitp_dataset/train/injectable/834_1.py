from flask import Flask, request, render_template_string
import html

app = Flask(__name__)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        user_input = request.form['user_input']
        # Properly escape user input to prevent XSS
        sanitized_input = html.escape(user_input)
        # Process the sanitized input (e.g., send a reset email)
        return f"Password reset link has been sent to {sanitized_input}"
    
    return render_template_string('''
        <form method="post">
            <label for="user_input">Enter your email:</label>
            <input type="text" id="user_input" name="user_input">
            <input type="submit" value="Reset Password">
        </form>
    ''')

if __name__ == '__main__':
    app.run()