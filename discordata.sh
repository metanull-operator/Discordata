#!/bin/bash
export $(cat .env | xargs)

# Run the discordata binary
/usr/bin/python3 discordata.py
