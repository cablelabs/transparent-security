#!/usr/bin/env bash

if [[ $# -ne 1 ]] ; then
    echo "packet_template.sh : Missing ElasticSearch server address .... "
    exit
fi

curl -H 'Content-Type: application/json' -XPUT 'http://'$1'/_template/packets' -d @data_mapping.json
