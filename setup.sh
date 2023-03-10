#!/bin/bash

APP_DIR=/opt/tw_github_app/config
CERT_FILE=/opt/tw_github_app/config/default.cert
KEY_FILE=/opt/tw_github_app/config/default.key

echo "Checking required components"
if ! docker info > /dev/null 2>&1; then
    echo "Docker not found. Please start docker and try again"
    exit 1
fi

echo "Setting up the ThreatWorx Github App"

mkdir -p $APP_DIR
if [ ! -d "$APP_DIR" ]; then
    echo "Could not create app directory $APP_DIR. Please check permissions"
    exit 1
fi

if [ -f "config/uwsgi.ini" ]; then
    cp -f config/uwsgi.ini $APP_DIR
else
    wget -O $APP_DIR/uwsgi.ini https://raw.githubusercontent.com/threatworx/github_app/master/config/uwsgi.ini
fi

if [ -f "config/config.ini" ]; then
    cp -f config/config.ini $APP_DIR
else
    wget -O $APP_DIR/config.ini https://raw.githubusercontent.com/threatworx/github_app/master/config/config.ini 
fi


if [ ! -f "$CERT_FILE" ]
then
	echo "Generating default self-signed certificates..."
	openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj "/C=US/O=tw_org/OU=tw_ou/CN=tw_gh_app_default"
	if [ $? -ne 0 ]; then
	    echo "Could not generate default self-signed cerfiticates"
	    exit 1
	fi
fi

docker pull threatworx/github_app_server:latest
if [ $? -ne 0 ]; then
    echo "Could not download docker app image"
    exit 1
fi

echo "Done"
