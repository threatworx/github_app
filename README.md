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

## Quick start - Install and configure the App Service

- Ensure requirements are satisfied on linux system, especially docker support and https inbound / outbound connectivity

- Download / clone the [ThreatWorx GitHub App](https://github.com/threatworx/github_app) repository

```bash
git clone https://github.com/threatworx/github_app.git
```

- Run the setup.sh script to create self signed certificates

```bash
cd github_app
./setup.sh
```

> If you have ssl certificates, copy them to the ``config`` directory and edit the ``uwsgi.ini`` file to use your certificates&nbsp;
> [uwsgi]&nbsp;
> ...&nbsp;
> https = =0,/opt/tw_github_app/config/``my.cert``,/opt/tw_github_app/config/``my.key``,...&nbsp;
> ...&nbsp;

- Start the app service by running the ``docker compose`` or the ``docker-compose`` command

```bash
docker compose up -d
```

- Point a browser to ``https://linux-system`` to configure the app service

> The browser will complain about the self signed certificate if are using one&nbsp;
> Please be sure to replace it with an appropriate ssl certificate

- Provide required details of your ThreatWorx subscription on the form 

- Select required options for app service and click ``Configure``

> These options can be changed later by editing the ``./config/config.ini`` file

- On the next page provide the name of your GitHub organization where this app will be deployed and click ``Deploy``

> If you are signed on to your enterprise GitHub account, the app will be available for installation in your Github Organization

- Follow instructions [here](https://docs.github.com/en/apps/maintaining-github-apps/installing-github-apps) to install the app for appropriate Github organizations

> If you are using self-signed certificates, make sure the SSL verification is disabled for Webhooks 

- Once the app is installed for an organization, select repositories as required to be scanned 

> App will initially do a complete dependency vulnerability scan for all selected repositories&nbsp;
> After that, any commits will trigger a rescan of the change that is committed&nbsp;
> If the PR workflow is enabled, each PR will be scanned and new vulnerabilities or code issues will be posted to the PR comments
