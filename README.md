# ThreatWorx GitHub App

## _Zero Trust Automated AppSec for Github Enterprise_

A complete automated AppSec solution part of the ThreatWorx proactive security platform which discovers your Enterprise GitHub repositories and finds vulnerable dependencies, run static tests on code and Infrastructure-As-Code files, finds embedded secrets and more.

It also has workflows to instantly check pull requests for vulnerabilities and code issues and report them to GitHub as comments for developer to see.

## Features

- Code doesn't leave your premises even for scanning - zero trust scan
- Packaged as a container for easy on-premise deployment
- Support for open source vulns and IaC scanning
- Workflows to scan PRs for open source vulns and IaC issues
- Support for on-premise / hosted GitHub Enterprise service
- Auto upgrade using watchtower

## Requirements

- Standard linux system (Redhat, Ubuntu, CentOS etc.) with docker support and port 443 (https) inbound / outbound connectivity
- SSL certificate for secure communication with GitHub (optional). App supports and will allow creating self signed certificates if none are available.
- Github App requires 'read' permissions for repo content and metadata and optional write permissions for PRs (in case you enable the PR workflow)

## Install the App Service

- Download / clone the [ThreatWorx GitHub App](https://github.com/threatworx/github_app) repository

```bash
git clone https://github.com/threatworx/github_app.git
```

- Run the setup.sh script to create self signed certificates if you don't have them

```bash
cd github_app
./setup.sh
```

> If you have ssl certificates, copy them to the ``config`` directory and edit the ``uwsgi.ini`` file to use your certificates
> [uwsgi]
> ...
> https = =0,/opt/tw_github_app/config/``my.cert``,/opt/tw_github_app/config/``my.key``,...
> ...

- Edit the ``config.ini`` file in ``config`` directory to update your ThreatWorx instance, user and API key

```bash
[threatworx]
handle=YOUR_TW_HANDLE
token=YOUR_TW_API_KEY
instance=YOUR_TW_INSTANCE
```
> instance is your dedicated ThreatWorx instance hostname e.g. acme.threatworx.io
> handle is your registered user email on the ThreatWorx instance e.g. bob@acme.com
> token is your API token that you can generate or copy from the ThreatWorx instance console by navigating to ``Profile`` -> ``Key Management`` in the left menu

- Modify any other features of the app service as required in the ``config.ini``

- Start the app service by running the docker compose command

```bash
cd ..
docker-compose up -d
```

## Configure and install the App in GitHub

- Open up a browser and sign in to your Enterprise Github account
- Point your browser to https://linux-docker-host/
- Enter the name of your organization where you would like to deploy the App in GitHub and click ``Create``
- Once the request is complete, deploy the App in the GitHub console for any organization of your choice just like any other app and add repositories to it


