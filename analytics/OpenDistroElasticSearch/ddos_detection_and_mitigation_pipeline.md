# DDOS Detection and Mitigation Pipeline ( UDPv4 ) using Open Distro Elasticsearch

- To add a DDOS Detection pipeline you need to add a monitor and an associated trigger to detect the DDOS attack.
- To add a DDOS Mitigation pipeline you need add an associated action (custom webhook) with associated trigger.

The same can be done using the Kibana UI or programmatically using the [Anomaloy Detection API]( https://opendistro.github.io/for-elasticsearch-docs/docs/ad/api/ ) and [Alerting API]( https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/api/ )

The below guides talks about using the Anomaloy Detection API and Alerting API.

> **_NOTE:_**
The guide is specific to DDOS use case. Please change the Anomaloy Detectors, Monitors, Triggers and Actions according to your use case.
[Official Guide](https://opendistro.github.io/for-elasticsearch-docs/)

## Add Anomaloy Detector
To create an Anomaloy Detector using the Kibana UI please look at [Official Guide](https://opendistro.github.io/for-elasticsearch-docs/docs/ad/) for more details.

Use below anomaly detection operations to programmatically create and manage detectors.

### Step 1: Create Anomaloy Detector

- Push it
```
curl -H 'Content-Type: application/json' -XPOST 'http://localhost:9200/_opendistro/_anomaly_detection/detectors' -d @anomaly_detector_config.json
```
- Expected Response
```
{
  "_id" : "UDkwkXUBenaD-0rLhn9b",
  "_version" : 1,
  "_seq_no" : 5,
  "_primary_term" : 1,
  "anomaly_detector" : {
    "name" : "ddos-anomaly-detector",
    "description" : "DDOS Anomaly Detector",
    "time_field" : "timestamp",
    "indices" : [
      "packets-*"
    ],
    "filter_query" : {
      "bool" : {
        "filter" : [
          {
            "term" : {
              "ts.IPVersion" : {
                "value" : "4",
                "boost" : 1.0
              }
            }
          },
          {
            "wildcard" : {
              "ts.INTMetadataSourceMetadataOriginatingMac" : {
                "wildcard" : "*000000000101*",
                "boost" : 1.0
              }
            }
          }
        ],
        "adjust_pure_negative" : true,
        "boost" : 1.0
      }
    },
    "detection_interval" : {
      "period" : {
        "interval" : 1,
        "unit" : "Minutes"
      }
    },
    "window_delay" : {
      "period" : {
        "interval" : 1,
        "unit" : "Minutes"
      }
    },
    "shingle_size" : 1,
    "schema_version" : 0,
    "feature_attributes" : [
      {
        "feature_id" : "STkwkXUBenaD-0rLhn9Z",
        "feature_name" : "UDP2DstPortValueCount",
        "feature_enabled" : true,
        "aggregation_query" : {
          "UDP2DstPortValueCount" : {
            "value_count" : {
              "field" : "ts.UDP2DstPort"
            }
          }
        }
      },
      {
        "feature_id" : "SjkwkXUBenaD-0rLhn9Z",
        "feature_name" : "IPVDstAddrValueCount",
        "feature_enabled" : true,
        "aggregation_query" : {
          "IPVDstAddrValueCount" : {
            "value_count" : {
              "field" : "ts.IPvDestAddr"
            }
          }
        }
      },
      {
        "feature_id" : "SzkwkXUBenaD-0rLhn9Z",
        "feature_name" : "OriginatingMacAddressValueCount",
        "feature_enabled" : true,
        "aggregation_query" : {
          "OriginatingMacAddressValueCount" : {
            "value_count" : {
              "field" : "ts.INTMetadataSourceMetadataOriginatingMac"
            }
          }
        }
      }
    ]
  }
}
```
- Verify it worked

The following GET call with appropriate _id can be made to check the newly created anomaly detector. The _id can be found in reponse of Step 1

```
curl -H 'Content-Type: application/json' -XPOST 'http://localhost:9200/_opendistro/_anomaly_detection/detectors/{_id}
```

- Start Anomaloy Detector

```
curl -H 'Content-Type: application/json' -XPOST 'http://localhost:9200/_opendistro/_anomaly_detection/detectors/{_id}/_start
```

### Step 2: Create Monitor

A monitor is a job that runs on a defined schedule and queries Elasticsearch. The results of these queries are then used as input for one or more triggers.

- Create custom SDN Webhook Alert Action to be associated with the Monitor

```
curl -H 'Content-Type: application/json' -XPOST 'http://localhost:9200/_opendistro/_alerting/destinations -d
'{
  "type": "custom_webhook",
  "name": "SDN_Webhook",
  "custom_webhook": {
    "path": "/aggAttack",
    "header_params": {
      "Content-Type": "application/json"
    },
    "scheme": "HTTP",
    "port": 9998,
    "host": "tps.sdn.org"
  }
}'
```
- Expected Response
```
{
  "_id" : "jjlCkXUBenaD-0rLO4Cg",
  "_version" : 1,
  "_seq_no" : 16,
  "_primary_term" : 1,
  "destination" : {
    "type" : "custom_webhook",
    "name" : "SDN_Webhook",
    "schema_version" : 2,
    "last_update_time" : 1604459838368,
    "custom_webhook" : {
      "path" : "/aggAttack",
      "header_params" : {
        "Content-Type" : "application/json"
      },
      "password" : null,
      "scheme" : "HTTP",
      "port" : 9998,
      "query_params" : { },
      "host" : "tps.sdn.org",
      "url" : null,
      "username" : null
    }
  }
}
```

> **_NOTE:_**
> Edit the /etc/hosts file on analytics instance to add the ubuntu private IP for dns name resolution to tps.sdn.org or any other preferred dns name. The DNS name added in hosts file should correspond to host properties in above payload.
> The _id from response will be utilized when creating the associated Monitor.

- Create Monitor

```
curl -H 'Content-Type: application/json' -XPOST 'http://localhost:9200/ _opendistro/_alerting/monitors -d
'{
  "type": "monitor",
  "name": "DDOS-Monitor",
  "enabled": true,
  "schedule": {
    "period": {
      "interval": 1,
      "unit": "MINUTES"
    }
  },
  "inputs": [{
    "search": {
      "indices": ["packets-*"],
      "query": {
        "size": 0,
        "query": {
        "bool": {
            "filter": [
                {
                    "range": {
                        "timestamp": {
                            "from": "{{period_end}}||-1m",
                            "to": "{{period_end}}",
                            "include_lower": true,
                            "include_upper": true,
                            "format": "epoch_millis",
                            "boost": 1
                        }
                    }
                }
            ],
            "adjust_pure_negative": true,
            "boost": 1
        }
    },
        "aggregations": {}
      }
    }
  }],
  "triggers": [{
    "name": "DDOS-Trigger",
    "severity": "1",
    "condition": {
      "script": {
        "source": "ctx.results[0].hits.total.value > 1000",
        "lang": "painless"
      }
    },
    "actions": [{
      "name": "Sdn-WebHook-Action",
      "destination_id": "jjlCkXUBenaD-0rLO4Cg",
      "message_template": {
        "source":"{\"event_action\":\"trigger\",\"payload\":{\"attack_type\":\"UDP Flood\",\"dst_ip\":\"192.168.1.10\",\"dst_port\":\"5792\",\"packet_size\":112,\"src_ip\":\"192.168.1.2\",\"src_mac\":\"00:00:00:00:01:01\"}}",
            "lang": "mustache",
            "options": {
                  "content_type": "application/json"
       }
     },
      "throttle_enabled": false
    }]
  }]
}'
```
> **_NOTE:_**
> The message_template property is specific to each brought up instance in tofino build environment and changes accordingly.

Once the associated monitor, trigger and action are configured you can test by sending packets specific to your testing scenario.
