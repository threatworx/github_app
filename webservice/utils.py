import sys
import os
import subprocess
import configparser
import requests
import time
import uuid
import tempfile
import json

from gidgethub import apps

config = None
GoDaddyCABundle = True
CONFIG_FILE = '/opt/tw_github_app/config/config.ini'
gh_app_manifest_state = None

def get_config(force_read = False):
    global config
    if force_read == False and config is not None:
        return config
    global CONFIG_FILE
    env_config_path = os.environ.get("TW_GITHUB_APP_CONFIG")
    if env_config_path is None:
        print("Warning environment variable [TW_GITHUB_APP_CONFIG] is not specified. Falling back to default path for config file [/opt/tw_github_app/config/config.ini]")
    elif os.path.isdir(env_config_path) == False:
        print("Error specified path [%s] in environment varliable [TW_GITHUB_APP_CONFIG] not found" % env_config_path)
        print("Error unable to start server...")
        sys.exit(1)
    else:
        CONFIG_FILE = env_config_path + os.path.sep + "config.ini"

    if os.path.isfile(CONFIG_FILE) == False:
        print("Error configuration file [%s] not found" % CONFIG_FILE)
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config

def write_config(config):
    with open(CONFIG_FILE, 'w') as fd:
        config.write(fd)

def get_gh_app_manifest_state():
    global gh_app_manifest_state
    if gh_app_manifest_state is not None:
        return gh_app_manifest_state
    gh_app_manifest_state = uuid.uuid4().hex
    return gh_app_manifest_state

def get_installation_access_token(installation_id):
    print("In get_installation_access_token")
    config = get_config()
    app_id=config['github_app']['app_id']
    private_key=config['github_app']['private_key']
    jwt_token = apps.get_jwt(app_id=app_id, private_key=private_key)
    #print(jwt_token)
    headers = { "Authorization": "Bearer %s" % jwt_token, "Accept": "application/vnd.github+json" }
    url = "https://api.github.com/app/installations/%s/access_tokens" % str(installation_id)
    response = requests_post(url, headers, {}, True)
    #print(response.status_code)
    #print(response.content)
    if response.status_code == 201:
        return response.json()
    else:
        return None

def discover_repo(gh_app_access_token, repo_url, branch, asset_id):

    # include access_token in git repo url to clone the repo for discovery
    updated_repo_url = "https://x-access-token:" + gh_app_access_token + '@' + repo_url.split('//')[1]

    config = get_config()
    handle = config['threatworx']['handle']
    token = config['threatworx']['token']
    instance = config['threatworx']['instance']
    dev_null_device = open(os.devnull, "w")

    twigs_cmd = "twigs -v --handle '%s' --token '%s' --instance '%s' --apply_policy SYNC_SCAN repo --repo '%s' --branch '%s' --assetid '%s' --assetname '%s'" % (handle, token, instance, updated_repo_url, branch, asset_id, asset_id)

    try:
        print("Starting asset discovery & scan for repo [%s] and branch [%s]" % (repo_url, branch))
        #print(twigs_cmd)
        #out = subprocess.check_output([twigs_cmd], shell=True)
        out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
        print("Asset discovery & scan completed")
        #print(out)
        return True
    except subprocess.CalledProcessError as e:
        print("Error running twigs discovery")
        print(e)
        return False

def set_requests_verify(verify):
    global GoDaddyCABundle
    GoDaddyCABundle = verify

def get_requests_verify():
    global GoDaddyCABundle
    return GoDaddyCABundle

def requests_get(url, headers, in_verify=None):
    in_verify = get_requests_verify() if in_verify is None else in_verify
    rc = 0
    st = 1
    while True:
        try:
            resp = requests.get(url, headers=headers, verify=in_verify)
            resp_status_code = resp.status_code
        except requests.exceptions.RequestException as e:
            print("Retry count [%s] got exception: [%s]" % (rc, str(e)))
            if rc >= 10:
                print("Max retries exceeded....giving up...")
                return None
            else:
                print("Sleeping for [%s] seconds..." % str(st))
                time.sleep(st)
                rc = rc + 1
                st = st * 2
                continue
        return resp

def requests_post(url, headers, json, in_verify=None):
    in_verify = get_requests_verify() if in_verify is None else in_verify
    rc = 0
    st = 1
    while True:
        try:
            resp =  requests.post(url, headers=headers, json=json, verify=in_verify)
        except requests.exceptions.RequestException as e:
            print("Retry count [%s] got exception in POST request: [%s]" % (rc, str(e)))
            if rc >= 10:
                print("Max retries exceeded for POST request....giving up...")
                return None
            else:
                print("Sleeping for [%s] seconds before next POST request..." % str(st))
                time.sleep(st)
                rc = rc + 1
                st = st * 2
                continue
        return resp

def requests_delete(url):
    rc = 0
    st = 1
    while True:
        try:
            resp =  requests.delete(url, verify=get_requests_verify())
        except requests.exceptions.RequestException as e:
            print("Retry count [%s] got exception in DELETE request: [%s]" % (rc, str(e)))
            if rc >= 10:
                print("Max retries exceeded for DELETE request....giving up...")
                return None
            else:
                print("Sleeping for [%s] seconds before next DELETE request..." % str(st))
                time.sleep(st)
                rc = rc + 1
                st = st * 2
                continue
        return resp

def compute_vuln_impact_delta(assetid1, assetid2):
    config = get_config()
    handle = config['threatworx']['handle']
    token = config['threatworx']['token']
    instance = config['threatworx']['instance']
    url = "https://" + instance + "/api/v1/asset_impact_delta/"
    auth_data = "?handle=" + handle + "&token=" + token + "&format=json"
    req_payload = { "asset1_id": assetid1, "asset2_id": assetid2 }
    print("Computing vulnerability impact delta between assets [%s] and [%s]" % (assetid1, assetid2))
    response = requests_post(url + auth_data, None, req_payload)
    if response.status_code != 200:
        print("Error computing vulnerability impact delta")
        print(response.status_code)
        print(response.content)
        return None
    else:
        return response.json()

def compose_pr_comment(impact_delta):
    asset2_only_vulns = impact_delta["asset2_only_vulns"]
    if len(asset2_only_vulns) == 0:
        return "No new vulnerabilities introduced in this pull request"
    else:
        prc = "Below is the list of new vulnerabilities introduced in this pull request:\n"
        for new_vuln in asset2_only_vulns:
            prc = prc + "Vulnerability ID: " + new_vuln["vuln_id"] + "\n"
            prc = prc + "CVSS Score: " + new_vuln["cvss_score"] + "\n"
            prc = prc + "Affected Product: " + new_vuln["affected_product"] + "\n"
            prc = prc + "-------------------------------------------------------------\n"
        return prc

def delete_asset(asset_id):
    config = get_config()
    handle = config['threatworx']['handle']
    token = config['threatworx']['token']
    instance = config['threatworx']['instance']
    url = "https://" + instance + "/api/v1/assets/"
    auth_data = "/?handle=" + handle + "&token=" + token + "&format=json"
    print("Deleting asset [%s]" % asset_id)
    response = requests_delete(url + asset_id + auth_data)
    if response.status_code != 200:
        print("Error deleting asset...")
        print(response.status_code)
        print(response.content)
    return response

async def process_pull_request(event_data):
    temp_json_file = tempfile.NamedTemporaryFile(mode='w', prefix='tw-', suffix='_ed.json', delete=False)
    temp_json_file_name = temp_json_file.name
    json.dump(event_data, temp_json_file)
    temp_json_file.close()
    base_path = os.path.dirname(os.path.realpath(__file__))
    cmd = base_path + os.sep + '/pull_request_handler -f ' + temp_json_file_name
    #print(cmd)
    proc = subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
