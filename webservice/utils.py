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

def create_diff_json(basefilename, headfilename):
    bf = open(basefilename, 'r')
    bf_json = json.loads(bf.read())
    hf = open(headfilename, 'r')
    hf_json = json.loads(hf.read())
    bf.close()
    hf.close()

    bf_set = set(bf_json['assets'][0]['products'])
    hf_set = set(hf_json['assets'][0]['products'])

    diff_set = hf_set - bf_set

    diff_products = list(diff_set)
    if len(diff_products) == 0:
        return None

    hf_json['assets'][0]['products'] = diff_products
    diff_json_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    diff_json_file.write(json.dumps(hf_json, ensure_ascii=False, indent=4))
    diff_json_file.close()
    return diff_json_file.name 

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
    config = get_config()
    app_id=config['github_app']['app_id']
    private_key=config['github_app']['private_key']
    jwt_token = apps.get_jwt(app_id=app_id, private_key=private_key)
    #print(jwt_token)
    headers = { "Authorization": "Bearer %s" % jwt_token, "Accept": "application/vnd.github+json" }
    url = "%s/app/installations/%s/access_tokens" % (config["github_app"]["github_api_url"], str(installation_id))
    response = requests_post(url, headers, {}, True)
    #print(response.status_code)
    #print(response.content)
    if response.status_code == 201:
        return response.json()
    else:
        print("Encountered error while getting access token")
        print(response.status_code)
        print(response.content)
        return None

def get_repo_metadata(gh_app_access_token, repo_full_name):
    config = get_config()
    repo_api_url = "%s/repos/%s" % (config["github_app"]["github_api_url"], repo_full_name)
    headers = { "Accept": "application/vnd.github+json", "Authorization" : "Bearer "+gh_app_access_token }
    response = requests_get(repo_api_url, headers, True)
    if response is not None and response.status_code == 200:
        return response.json()
    else:
        print("Unable to get JSON metadata for repo [%s]" % repo_full_name)
        print(response.status_code)
        print(response.content)
        return None

def get_installation_repositories(gh_app_access_token):
    config = get_config()
    repo_api_url = "%s/installation/repositories?per_page=100&page=%s"
    headers = { "Accept": "application/vnd.github+json", "Authorization" : "Bearer "+gh_app_access_token }
    page_no = 1
    repos_list = []
    while True:
        temp_repo_api_url = repo_api_url % (config["github_app"]["github_api_url"], page_no)
        response = requests_get(temp_repo_api_url, headers, True)
        if response is not None and response.status_code == 200:
            repos = response.json()['repositories']
            if len(repos) == 0:
                break
            for repo in repos:
                repos_list.append(repo['full_name'])
            page_no = page_no + 1
    return repos_list

def scan_diff(asset_id, diff_json_file):
    config = get_config()
    handle = config['threatworx']['handle']
    token = config['threatworx']['token']
    instance = config['threatworx']['instance']
    dev_null_device = open(os.devnull, "w")
    ssl_verification = config['threatworx'].getboolean('ssl_verification', fallback=True)
    insecure = "" if ssl_verification else "--insecure"

    twigs_cmd = "twigs -v %s --handle '%s' --token '%s' --instance '%s' --create_empty_asset --apply_policy SYNC_SCAN --run_id github_app sbom --input '%s' --standard threatworx --format json" % (insecure, handle, token, instance, diff_json_file)
    print("Starting scan for diff asset [%s]" % (asset_id))

    try:
        out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
        print("Asset discovery & scan completed")
        return True
    except subprocess.CalledProcessError as e:
        print("Error running twigs discovery")
        print(e)
        return False

def discover_repo_wrapper(data):
    repo_full_name = data[0]
    installation_id = data[1]
    # get the installation access token for our GitHub App
    installation_access_token = get_installation_access_token(installation_id)
    #print(installation_access_token)

    repo_url = "https://%s/%s.git" % (config["github_app"]["github_host"], repo_full_name)
    asset_id = repo_full_name.replace('/','_') # don't include default branch

    # Discover and scan asset
    ret_val = discover_repo(installation_access_token['token'], repo_url, None, asset_id)

    if ret_val == False:
        print("Error while discovering asset for default branch")

def discover_repo(gh_app_access_token, repo_url, branch, asset_id, base_discovery=True, no_scan=False, outfile=None, run_iac_checks=True):

    # include access_token in git repo url to clone the repo for discovery
    updated_repo_url = "https://x-access-token:" + gh_app_access_token + '@' + repo_url.split('//')[1]

    config = get_config()
    handle = config['threatworx']['handle']
    token = config['threatworx']['token']
    instance = config['threatworx']['instance']
    iac_checks_enabled = config['github_app'].getboolean('iac_checks_enabled')
    code_sharing = config['github_app'].getboolean('code_sharing')
    ssl_verification = config['threatworx'].getboolean('ssl_verification', fallback=True)
    insecure = "" if ssl_verification else "--insecure"
    dev_null_device = open(os.devnull, "w")
    org = repo_url.split('//')[1].split('/')[1]
    tags = config['github_app'].get('user_tags')
    tags = '' if tags is None else tags.strip()
    tags = tags.split(',')
    ptags = "--tag '%s'" % (org)
    for tag in tags:
        tag = tag.strip()
        if tag == "":
            continue # skip empty tags
        ptags = "%s --tag '%s'" % (ptags, tag)
    #print("Tags: %s" % ptags)

    if base_discovery:
        if no_scan:
            twigs_cmd = "twigs -v --handle '%s' --create_empty_asset --no_scan --out '%s' --run_id github_app repo --repo '%s' --assetid '%s' --assetname '%s'" % (handle, outfile, updated_repo_url, asset_id, asset_id)
            print("Starting asset discovery for repo [%s] and branch [%s]" % (repo_url, branch))
        else:
            twigs_cmd = "twigs -v %s --handle '%s' --token '%s' --instance '%s' %s --create_empty_asset --apply_policy SYNC_SCAN --run_id github_app repo --repo '%s' --assetid '%s' --assetname '%s'" % (insecure, handle, token, instance, ptags, updated_repo_url, asset_id, asset_id)
            print("Starting asset discovery & scan for repo [%s] and branch [%s]" % (repo_url, branch))
        if branch is not None:
            twigs_cmd = twigs_cmd + " --branch '%s'" % branch

        # Run base asset discovery
        try:
            #print(twigs_cmd)
            #out = subprocess.check_output([twigs_cmd], shell=True)
            out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
            print("Base asset discovery completed")
            #print(out)
        except subprocess.CalledProcessError as e:
            print("Error running twigs discovery")
            print(e)
            return False

    # Perform IaC checks if enabled and specified to be run
    if iac_checks_enabled and run_iac_checks:
        if no_scan:
            twigs_cmd = "twigs -v --handle '%s' --create_empty_asset --no_scan --out '%s' --run_id github_app repo --repo '%s' --assetid '%s' --assetname '%s' --iac_checks" % (handle, outfile, updated_repo_url, asset_id, asset_id)
            print("Running IaC checks for repo [%s] and branch [%s]" % (repo_url, branch))
        else:
            twigs_cmd = "twigs -v %s --handle '%s' --token '%s' --instance '%s' %s --create_empty_asset --no_scan --run_id github_app repo --repo '%s' --assetid '%s' --assetname '%s' --iac_checks" % (insecure, handle, token, instance, ptags, updated_repo_url, asset_id, asset_id)
            print("Running IaC checks for repo [%s] and branch [%s]" % (repo_url, branch))
        if branch is not None:
            twigs_cmd = twigs_cmd + " --branch '%s'" % branch
        if code_sharing == False:
            twigs_cmd = twigs_cmd + " --no_code"
        try:
            #print(twigs_cmd)
            #out = subprocess.check_output([twigs_cmd], shell=True)
            out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
            print("IaC checks completed")
            #print(out)
            return True
        except subprocess.CalledProcessError as e:
            print("Error running twigs IaC checks")
            print(e)
            return False
    else:
        return True

def set_requests_verify(verify):
    global GoDaddyCABundle
    GoDaddyCABundle = verify

def get_requests_verify():
    global GoDaddyCABundle
    config = get_config()
    ssl_verification = config['threatworx'].getboolean('ssl_verification', fallback=True)
    if ssl_verification:
        return GoDaddyCABundle
    else:
        return False

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
    filter = config['github_app'].get('pr_vulnerability_filter')
    if filter is not None and len(filter.strip()) > 0:
        req_payload['filter'] = json.loads(filter.strip())
    print("Computing vulnerability impact delta between assets [%s] and [%s]" % (assetid1, assetid2))
    #print(req_payload)
    response = requests_post(url + auth_data, None, req_payload)
    if response.status_code != 200:
        print("Error computing vulnerability impact delta")
        print(response.status_code)
        print(response.content)
        return None
    else:
        return response.json()

def get_impacts(assetid):
    config = get_config()
    handle = config['threatworx']['handle']
    token = config['threatworx']['token']
    instance = config['threatworx']['instance']
    url = "https://" + instance + "/api/v1/impacts/"
    auth_data = "?handle=" + handle + "&token=" + token + "&format=json"
    req_payload = { "asset_ids": [assetid] }
    filter = config['github_app'].get('pr_vulnerability_filter')
    if filter is not None and len(filter.strip()) > 0:
        req_payload['filter'] = json.loads(filter.strip())
    print("Getting vulnerability impacts for asset [%s]" % (assetid))
    #print(req_payload)
    response = requests_post(url + auth_data, None, req_payload)
    if response.status_code != 200:
        print("Error vulnerability impacts")
        print(response.status_code)
        print(response.content)
        return None
    else:
        return response.json()

def compose_pr_comment(impacts):
    diff_vulns = impacts["impacts"]
    if len(diff_vulns) == 0:
        return "No new vulnerabilities introduced in this pull request"
    else:
        config = get_config()
        instance = config['threatworx']['instance']
        prc = "Below is the list of new vulnerabilities introduced in this pull request:\n"
        #prc = prc + "\n|Field|Value|\n|:---|:---|\n"
        for new_vuln in diff_vulns:
            prc = prc + "\n|   |   |\n|:---|:---|\n"
            vuln_url = "https://%s/i3/#/threat/%s" % (instance, new_vuln["vuln_id"])
            prc = prc + "|Vulnerability ID|" + "[" + new_vuln["vuln_id"] + "](" + vuln_url + ")|\n"
            prc = prc + "|CVSS Score|" + new_vuln["cvss_score"] + "|\n"
            prc = prc + "|Reference|" + new_vuln["vuln_url"] + "|\n"
            prc = prc + "|Affected Dependency|" + new_vuln["affected_product"] + "|\n"
            prc = prc + "|Dependency found in file|" + new_vuln["dependency_file"] + "|\n"
            prc = prc + "|Recommendation|" + new_vuln["recommendation"] + "|\n"
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

def launch_request_handler_process(python_script_name, event_data):
    temp_json_file = tempfile.NamedTemporaryFile(mode='w', prefix='tw-', suffix='_ed.json', delete=False)
    temp_json_file_name = temp_json_file.name
    json.dump(event_data, temp_json_file)
    temp_json_file.close()
    base_path = os.path.dirname(os.path.realpath(__file__))
    cmd = base_path + os.sep + python_script_name + ' -f ' + temp_json_file_name
    #print(cmd)
    proc = subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)

def process_pull_request(event_data):
    launch_request_handler_process('pull_request_handler', event_data)

def process_push_request(event_data):
    launch_request_handler_process('push_request_handler', event_data)

def process_repos_added_request(event_data):
    launch_request_handler_process('repos_added_request_handler', event_data)

def process_repos_removed_request(event_data):
    launch_request_handler_process('repos_removed_request_handler', event_data)

def process_installation_created_request(event_data):
    launch_request_handler_process('installation_created_request_handler', event_data)

def process_installation_deleted_request(event_data):
    launch_request_handler_process('installation_deleted_request_handler', event_data)

def process_installation_unsuspend_request(event_data):
    launch_request_handler_process('installation_unsuspend_request_handler', event_data)

