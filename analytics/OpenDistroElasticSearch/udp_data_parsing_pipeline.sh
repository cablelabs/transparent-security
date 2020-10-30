#!/usr/bin/env bash

if [[ $# -ne 1 ]] ; then
    echo "usage: udp_data_parsing.sh node"
    exit
fi

curl -H 'Content-Type: application/json' -XPUT 'http://'$1'/_injest/pipeline/ts_parsing' -d @udp_data_parsing.json
