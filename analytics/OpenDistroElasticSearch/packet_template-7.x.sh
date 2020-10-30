#!/usr/bin/env bash

if [[ $# -ne 1 ]] ; then
    echo "usage: packet_template.sh node"
    exit
fi

curl -H 'Content-Type: application/json' -XPUT 'http://'$1'/_template/packets' -d @data_mapping.json
