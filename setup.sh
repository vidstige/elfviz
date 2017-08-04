#!/bin/sh
set -e
python3 -m venv venv/
venv/bin/python3 -m pip --disable-pip-version-check install wheel
venv/bin/python3 -m pip --disable-pip-version-check install -r requirements.txt
