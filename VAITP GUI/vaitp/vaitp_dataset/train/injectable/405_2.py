```python
"""
Defines helper methods useful for setting up ports, launching servers, and handling `ngrok`
"""

import os
import socket
import threading
from flask import Flask, request, session, jsonify, abort, send_file, render_template, redirect
from flask_cachebuster import CacheBuster
from flask_login import LoginManager, login_user, current_user, login_required
from flask_cors import CORS
import threading
import pkg_resources
import datetime
import time
import json
import urllib.request
from shutil import copyfile
import requests
import sys
import csv
import logging
from gradio.tunneling import create_tunnel
from gradio import encryptor
from gradio import queue
from functools import wraps
import io
import inspect
import traceback
from werkzeug.security import safe_join, check_password_hash, generate_password_hash

INITIAL_PORT_VALUE = int(os.getenv(
    'GRADIO_SERVER_PORT', "7860"))  # The http server will try to open on port 7860. If not available, 7861, 7862, etc.
TRY_NUM_PORTS = int(os.getenv(
    'GRADIO_NUM_PORTS', "100"))  # Number of ports to try before giving up and throwing an exception.
LOCALHOST_NAME = os.getenv(
    'GRADIO_SERVER_NAME', "127.0.0.1")
GRADIO_API_SERVER = "https://api.gradio.app/v1/tunnel-request"
GRADIO_FEATURE_ANALYTICS_URL = "https://api.gradio.app/gradio-feature-analytics/"

STATIC_TEMPLATE_LIB = pkg_resources.resource_filename("gradio", "templates/")
STATIC_PATH_LIB = pkg_resources.resource_filename("gradio", "templates/frontend/static")
VERSION_FILE = pkg_resources.resource_filename("gradio", "version.txt")
with open(VERSION_FILE) as version_file:
    GRADIO_STATIC_ROOT = "https://gradio.s3-us-west-2.amazonaws.com/" + \
        version_file.read().strip() + "/static/"

app = Flask(__name__,
            template_folder=STATIC_TEMPLATE_LIB,
            static_folder="",
            static_url_path="/none/")
app.url_map.strict_slashes = False

CORS(app)
cache_buster = CacheBuster(
    config={'extensions': ['.js', '.css'], 'hash_size': 5})
cache_buster.init_app(app)
app.secret_key = os.getenv("GRADIO_KEY", "secret")
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Hide Flask default message
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None


class User:
    def __init__(self, id):
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
        self.id = id

    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(_id):
    return User(_id)


def login_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if app.auth:
            @login_required
            def func2(*args, **kwargs):
                return func(*args, **kwargs)

            return func2(*args, **kwargs)
        else:
            return func(*args, **kwargs)
    return wrapper


def get_local_ip_address():
    try:
        ip_address = requests.get('https://api.ipify.org', timeout=3).text
    except (requests.ConnectionError, requests.exceptions.ReadTimeout):
        ip_address = "No internet connection"
    return ip_address


IP_ADDRESS = get_local_ip_address()


def get_first_available_port(initial, final):
    """
    Gets the first open port in a specified range of port numbers
    :param initial: the initial value in the range of port numbers
    :param final: final (exclusive) value in the range of port numbers, should be greater than `initial`
    :return:
    """
    for port in range(initial, final):
        try:
            s = socket.socket()  # create a socket object
            s.bind((LOCALHOST_NAME, port))  # Bind to the port
            s.close()
            return port
        except OSError:
            pass
    raise OSError(
        "All ports from {} to {} are in use. Please close a port.".format(
            initial, final
        )
    )


@app.route("/", methods=["GET"])
@login_check
def main():
    session["state"] = None
    return render_template("frontend/index.html", config=app.interface.config)


@app.route("/static/<path:path>", methods=["GET"])
def static_resource(path):
    if app.interface.share:
        return redirect(GRADIO_STATIC_ROOT + path)
    else:
        return send_file(safe_join(STATIC_PATH_LIB, path))


# TODO(@aliabid94): this throws a 500 error if app.auth is None (should probalbly just redirect to '/')
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        config = get_config()
        return render_template("frontend/index.html", config=config)
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if ((not callable(app.auth) and username in app.auth and check_password_hash(app.auth[username], password))
                or (callable(app.auth) and app.auth.__call__(username, password))):
            login_user(User(username))
            return redirect("/")
        else:
            return abort(401)


@app.route("/config/", methods=["GET"])
def get_config():
    if app.interface.auth is None or current_user.is_authenticated:
        return jsonify(app.interface.config)
    else:
        return {"auth_required": True, "auth_message": app.interface.auth_message}


@app.route("/enable_sharing/<path:path>", methods=["GET"])
@login_check
def enable_sharing(path):
    if path == "None":
        path = None
    app.interface.config["share_url"] = path
    return jsonify(success=True)


@app.route("/shutdown", methods=['GET'])
def shutdown():
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        raise RuntimeError('Not running werkzeug')
    shutdown_func()
    return "Shutting down..."


@app.route("/api/predict/", methods=["POST"])
@login_check
def predict():
    raw_input = request.json["data"]
    # Capture any errors made and pipe to front end
    if app.interface.show_error:
        try:
            prediction, durations = app.interface.process(raw_input)
        except BaseException as error:
            traceback.print_exc()
            return jsonify({"error": str(error)}), 500
    else:
        prediction, durations = app.interface.process(raw_input)
    avg_durations = []
    for i, duration in enumerate(durations):
        app.interface.predict_durations[i][0] += duration
        app.interface.predict_durations[i][1] += 1
        avg_durations.append(app.interface.predict_durations[i][0] 
            / app.interface.predict_durations[i][1])
    app.interface.config["avg_durations"] = avg_durations
    output = {"data": prediction, "durations": durations, "avg_durations": avg_durations}
    if app.interface.allow_flagging == "auto":
        try:
            flag_index = flag_data(raw_input, prediction, 
                flag_option=(None if app.interface.flagging_options is None else ""), 
                username=current_user.id if current_user.is_authenticated else None)
            output["flag_index"] = flag_index
        except Exception as e:
            print(str(e))
            pass
    return jsonify(output)


def get_types(cls_set, component):