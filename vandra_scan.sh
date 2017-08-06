#!bin/sh
# Scans the vandra_scan binary
venv/bin/python3 track.py $(find ../Reconstruction/komb/installdir_relwithdebinfo -name "*.a" | sed -e 's/^/-L/') ../Reconstruction/komb/installdir_release/bin/vandra_scan