#!/bin/bash

if [ $# -lt 2 ]; then
  echo "Usage: $0 <le-mail> <domains>..."
  exit 1
fi

email=$1
args=("$@") 
domains=("${args[@]:1}")
script_dir=$(dirname "$0")

for domain in ${domains[@]}; do
  # no need to reload every time, just do it at the end of the batch
  "$script_dir/renew-haproxy-cert.py" --domain "$domain" --mail "$email" --no-reload --silent
done

systemctl reload haproxy