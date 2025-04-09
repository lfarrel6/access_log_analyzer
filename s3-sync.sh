#!/usr/bin/env sh

echo "Syncing: $1"
aws s3 sync $1 ./assets

echo "Extracting logs in ./assets"
ls ./assets/*.gz | gxargs gunzip