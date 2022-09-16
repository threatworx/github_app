#!/bin/bash
# Install github app dependencies
pip -r /tmp/requirements.txt

# Cleanup /tmp
rm -f /tmp/*
