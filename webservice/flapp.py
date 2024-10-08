import os
import sys
import traceback

from flask import Flask
from flask import request, redirect
from gidgethub import sansio

from . import utils

app = Flask(__name__)
utils.set_requests_verify(os.path.dirname(os.path.realpath(__file__)) + os.sep + 'gd-ca-bundle.crt')

@app.route('/')
def index_page():
    rurl = request.host_url+'configure'
    return redirect(rurl, code=302)

@app.route("/configure")
def handle_configure_github_app():
    print("Configure app service")
    config = utils.get_config()
    if config['github_app'].getboolean('setup_done'):
        print("Warning app aervice is already setup")
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/setup_done.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}

    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/github_app_config.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    return fc, 200, {'Content-Type': 'text/html'}

@app.route("/save_config", methods=['POST'])
def handle_save_github_app_config():
    print("Save app service configuration")
    config = utils.get_config()
    if config['github_app'].getboolean('setup_done'):
        print("Warning app service is already setup")
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/setup_done.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}

    # update configuration
    tw_handle = request.values.get('tw_handle')
    tw_api_key = request.values.get('tw_api_key')
    tw_instance = request.values.get('tw_instance')
    sast_enabled = request.values.get('sast_enabled')
    iac_enabled = request.values.get('iac_enabled')
    secrets_enabled = request.values.get('secrets_enabled')
    custom_password_file = request.values.get('custom_password_file')
    code_sharing_enabled = request.values.get('code_sharing_enabled')
    pr_workflow_enabled = request.values.get('pr_workflow_enabled')
    tw_gh_host = request.values.get('tw_gh_host')
    tw_gh_api_url = request.values.get('tw_gh_api_url')
    tw_user_tags = request.values.get('tw_user_tags')
    config['threatworx']['handle'] = tw_handle
    config['threatworx']['token'] = tw_api_key
    config['threatworx']['instance'] = tw_instance
    config['github_app']['github_host'] = tw_gh_host
    config['github_app']['github_api_url'] = tw_gh_api_url
    config['github_app']['user_tags'] = tw_user_tags
    config['github_app']['custom_password_file'] = custom_password_file.strip() if custom_password_file is not None else ""
    config['github_app']['sast_checks_enabled'] = 'true' if sast_enabled == 'yes' else 'false'
    config['github_app']['iac_checks_enabled'] = 'true' if iac_enabled == 'yes' else 'false'
    config['github_app']['secrets_checks_enabled'] = 'true' if secrets_enabled == 'yes' else 'false'
    config['github_app']['code_sharing'] = 'true' if code_sharing_enabled == 'yes' else 'false'
    config['github_app']['pr_workflow_enabled'] = 'true' if pr_workflow_enabled == 'yes' else 'false'
    utils.write_config(config)
    config = utils.get_config(True)

    # redirect to next step
    rurl = request.host_url + '/../deploy'
    return redirect(rurl, code=302)

@app.route("/deploy")
def handle_create_github_app():
    print("Deploying github app")
    config = utils.get_config()
    if config['github_app'].getboolean('setup_done'):
        print("Warning GitHub App is already setup")
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/setup_done.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}

    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/github_app_create.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    fc = fc.replace("TW_STATE", utils.get_gh_app_manifest_state())
    fc = fc.replace("GH_HOST", config["github_app"]["github_host"])
    return fc, 200, {'Content-Type': 'text/html'}

@app.route("/redirect")
def redirect_handler():
    try:
        print("Handling GitHub redirect")
        #print(request.values)
        config = utils.get_config()
        if config['github_app'].getboolean('setup_done'):
            print("Error ignoring additional redirect handler call as GitHub App is already setup")
            return "GitHub App is already setup", 200, {'Content-Type': 'text/plain'}
        code = request.values.get('code')
        state = request.values.get('state')
        if state != utils.get_gh_app_manifest_state():
            print("Error security state mismatch, possible CSRF attack")
            return "Error security state mismatch, possible CSRF attack", 200, {'Content-Type': 'text/plain'}
        api_url = "%s/app-manifests/%s/conversions" % (config["github_app"]["github_api_url"], code)
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
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/success.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return "Internal Server Error", 500, {'Content-Type': 'text/plain'}

@app.route("/webhook", methods=['POST'])
def webhook():
    try:
        #print(request.data)
        config = utils.get_config()
        secret = config['github_app']['webhook_secret']
        base_discovery_enabled = config['github_app'].getboolean('base_discovery_enabled')
        pr_enabled = config['github_app'].getboolean('pr_workflow_enabled')
        event = sansio.Event.from_http(request.headers, request.data, secret=secret)
        #print("%s - %s" % (event.event, event.data["action"]))
        if event.event == "pull_request" and (event.data["action"] == "opened" or event.data["action"] == "reopened" or event.data["action"] == "synchronize") and pr_enabled:
            print("Handling pull_request opened webhook")
            utils.process_pull_request(event.data)
        if event.event == "push" and not event.data["ref"].startswith("refs/tags/") and len(event.data["commits"]) > 0 and base_discovery_enabled:
                utils.process_push_request(event.data)
        if event.event == "installation" and (event.data["action"] == "created" or event.data["action"] == "deleted" or event.data["action"] == "unsuspend") and base_discovery_enabled:
            print("Handling installation webhook for [%s]" % event.data["action"])
            if event.data["action"] == "created":
                utils.process_installation_created_request(event.data)
            elif event.data["action"] == "deleted":
                utils.process_installation_deleted_request(event.data)
            elif event.data["action"] == "unsuspend":
                utils.process_installation_unsuspend_request(event.data)
        if event.event == "installation_repositories" and (event.data["action"] == "added" or event.data["action"] == "removed") and base_discovery_enabled:
            print("Handling installation_webhook for repositories [%s]" % event.data["action"])
            if event.data["action"] == "added":
                utils.process_repos_added_request(event.data)
            elif event.data["action"] == "removed":
                utils.process_repos_removed_request(event.data)

        return "", 200, {'Content-Type': 'text/plain'}
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return "Internal Server Error", 500, {'Content-Type': 'text/plain'}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int("80"))
