#!/bin/bash
export $(cat .env | xargs)

# Run the discordata binary
/usr/bin/python3 mock-webhook-request.py $@
