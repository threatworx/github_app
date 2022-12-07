#!/bin/bash
# Install github app dependencies
pip install -r /tmp/requirements.txt
echo "/usr/local/bin/uwsgi --ini /opt/tw_github_app/config/uwsgi.ini" >> /usr/local/bin/twigs-update.sh
mv /usr/local/bin/twigs-update.sh /usr/local/bin/update-twigs-run-uwsgi.sh
# Cleanup /tmp
rm -f /tmp/*
