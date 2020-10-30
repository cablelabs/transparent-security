# UDP Data Mapping and Parsing Guide for ElasticSearch

- Default configured ElasticSearch instance runs on port 9200.
- Default configured Kibana instance runs on port 5601.

## Adding UDP data templates to ElasticSearch for incoming packets
- To manually add UDP data templates for incoming UDP packets please run packet_template-7.x.sh script. The script takes ElasticSearch address and port number as first argument.
- Push it
```
 ./packet_template-7.x.sh localhost:9200
```

## Adding UDP data parsing to ElasticSearch for incoming packets
- To manually add UDP data parsing using Painless API for incoming UDP packets please run udp_data_parsing_pipeline.sh script. The script takes ElasticSearch address and port number as first argument.
- Push it
```
  ./udp_data_parsing_pipeline.sh localhost:9200
```

## Commands to test added UDP templates and parsing pipeline for incoming packets

- To verify added UDP data template run the following ...

```
   curl -H 'Content-Type: application/json' -XGET 'http://localhost:9200/_template/packets'
```

- To verify added UDP data parsing pipeline run the following ...

```
   curl -H 'Content-Type: application/json' -XGET 'http://localhost:9200/_ingest/pipeline/ts_parsing'
```
