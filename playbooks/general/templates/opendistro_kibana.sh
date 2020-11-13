server.port:  5601
server.host: 0.0.0.0
elasticsearch.hosts: http://localhost:9200
elasticsearch.ssl.verificationMode: none
#elasticsearch.username: admin
#elasticsearch.password: admin
#elasticsearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
​
#opendistro_security.multitenancy.enabled: true
#opendistro_security.multitenancy.tenants.preferred: ["Private", "Global"]
#opendistro_security.readonly_mode.roles: ["kibana_read_only"]
​
# Use this setting if you are running kibana without https
#opendistro_security.cookie.secure: false
​
newsfeed.enabled: false
telemetry.optIn: false
telemetry.enabled: false
