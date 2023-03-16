#!/bin/bash

CERT_FILE=./config/default.cert
KEY_FILE=./config/default.key

echo "Generating default self-signed certificates..."
if [ ! -f "$CERT_FILE" ]
then
	openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj "/C=US/O=tw_org/OU=tw_ou/CN=tw_gh_app_default"
	if [ $? -ne 0 ]; then
	    echo "Could not generate default self-signed cerfiticates"
	    exit 1
	fi
fi

echo "Done"
