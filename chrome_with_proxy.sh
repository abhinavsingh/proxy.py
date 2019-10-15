#!/bin/bash

/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --no-first-run \
  --no-default-browser-check \
  --user-data-dir="$(mktemp -d -t 'chrome-remote_data_dir')" \
  --proxy-server=localhost:8899
