#!/bin/bash
export $(cat .env | xargs)

# Run the discordata binary
./discordata
