#!/bin/bash
FLASK_APP=elfviz FLASK_DEBUG=1 venv/bin/python3 -m flask run "$@"
