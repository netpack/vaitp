
from flask import Flask, render_template, request, session, redirect, make_response
import os
import sys
import requests
import jwt
import uuid
from urllib.parse import urlencode

CLIENT_ID = 'valtech.idp.testclient.local'
CLIENT_SECRET = os.environ['CLIENT_SECRET']

app = Flask(__name__, static_url_path='')
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    signed_in = session.get('signed_in') is True
    header = 'Not signed in'
    text = 'Click the button below to sign in.'

    if signed_in:
        header = 'Welcome!'
        text = 'Signed in as %s.' % session['email']

    return render_template('index.html', header=header, text=text)

@app.route('/sign-in')
def sign_in():
    if session.get('signed_in') is True:
        return redirect('/')

    state = str(uuid.uuid4())
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'scope': 'email openid',
        'state': state
    }

    authorize_url = 'https://stage-id.valtech.com/oauth2/authorize?' + urlencode(params)

    resp = make_response(redirect(authorize_url))
    resp.set_cookie('csrf_token', state, httponly=True, secure=True, samesite='Strict')
    return resp

@app.route('/sign-in/callback')
def sign_in_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    csrf_token = request.cookies.get('csrf_token')

    if not state or state != csrf_token:
        raise Exception("Possible CSRF detected (state does not match stored state)")

    tokens = exchange_code_for_tokens(code)

    id_token = tokens.get("id_token")
    if not id_token:
        raise Exception("No id_token received")

    try:
      user_info = jwt.decode(id_token, key=None, algorithms=["RS256"], options={"verify_signature": False})
    except jwt.exceptions.PyJWTError as e:
      raise Exception(f"Error decoding id_token: {e}")
    
    if not user_info or not user_info.get('email'):
        raise Exception("Email not found in id_token")
    
    session['signed_in'] = True
    session['email'] = user_info['email']

    resp = make_response(redirect('/'))
    resp.set_cookie('csrf_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
    return resp

@app.route('/sign-out')
def sign_out():
    session.clear()
    return redirect('https://stage-id.valtech.com/oidc/end-session?client_id=%s' % CLIENT_ID)

def exchange_code_for_tokens(code):
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    res = requests.post('https://stage-id.valtech.com/oauth2/token', data=data, verify=True)
    res.raise_for_status()
    return res.json()

def fetch_user_info(access_token):
    res = requests.get('https://stage-id.valtech.com/api/users/me', headers={'Authorization': 'Bearer %s' % access_token}, verify=True)
    res.raise_for_status()
    return res.json()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, ssl_context='adhoc')