import os
import sys
import traceback

from flask import Flask
from flask import request
from gidgethub import sansio

from . import utils

app = Flask(__name__)
utils.set_requests_verify(os.path.dirname(os.path.realpath(__file__)) + os.sep + 'gd-ca-bundle.crt')

@app.route("/create_github_app")
def handle_get():
    print("In create_github_app handler")
    config = utils.get_config()
    if config['github_app'].getboolean('setup_done'):
        print("Warning GitHub App is already setup")
        return "GitHub App is already setup", 200, {'Content-Type': 'text/plain'}

    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/github_app_config.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    fc = fc.replace("TW_STATE", utils.get_gh_app_manifest_state())
    return fc, 200, {'Content-Type': 'text/html'}

@app.route("/redirect")
def redirect_handler():
    try:
        print("In redirect handler")
        #print(request.values)
        config = utils.get_config()
        if config['github_app'].getboolean('setup_done'):
            print("Error Ignoring additional redirect handler call as GitHub App is already setup")
            return "GitHub App is already setup", 200, {'Content-Type': 'text/plain'}
        code = request.values.get('code')
        state = request.values.get('state')
        if state != utils.get_gh_app_manifest_state():
            print("Error security state mismatch, possible CSRF attack")
            return "Error security state mismatch, possible CSRF attack", 200, {'Content-Type': 'text/plain'}
        api_url = "https://api.github.com/app-manifests/%s/conversions" % code
        response = utils.requests_post(api_url, { "Accept": "application/vnd.github+json" }, { }, True)
        response = response.json()
        #print(response)
        app_id = str(response['id'])
        private_key = response['pem']
        webhook_secret = response['webhook_secret']
        config['github_app']['app_id'] = app_id
        config['github_app']['private_key'] = private_key
        config['github_app']['webhook_secret'] = webhook_secret
        config['github_app']['setup_done'] = 'true'
        utils.write_config(config)
        config = utils.get_config(True)
        print("Updated GitHub App Configuration")
        return "Your GitHub App is installed successfully", 200, {'Content-Type': 'text/plain'}
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return "Internal Server Error", 500, {'Content-Type': 'text/plain'}

@app.route("/webhook", methods=['POST'])
def webhook():
    try:
        #print(request.data)
        config = utils.get_config()
        secret = config['github_app']['webhook_secret']
        event = sansio.Event.from_http(request.headers, request.data, secret=secret)
        if event.event == "pull_request" and (event.data["action"] == "opened" or event.data["action"] == "reopened"):
            print("In pull_request opened webhook")
            utils.process_pull_request(event.data)
        return "", 200, {'Content-Type': 'text/plain'}
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return "Internal Server Error", 500, {'Content-Type': 'text/plain'}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int("80"))
