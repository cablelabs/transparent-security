#!/usr/bin/env bash

if [[ $# -ne 1 ]] ; then
    echo "udp_data_parsing.sh : Missing ElasticSearch server address .... "
    exit
fi

curl -H 'Content-Type: application/json' -XPUT 'http://'$1'/_ingest/pipeline/ts_parsing' -d @udp_data_parsing.json
