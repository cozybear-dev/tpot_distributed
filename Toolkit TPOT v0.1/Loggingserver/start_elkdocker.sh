#!/bin/bash
sysctl -w vm.max_map_count=262144
docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 \
  -v elk-data:/var/lib/elasticsearch --net=host --restart unless-stopped -it sebp/elk:custom
docker run -d -p 3030:3030 --restart unless-stopped \
  -v /etc/elastalert/config/elastalert.yaml:/opt/elastalert/config.yaml \
  -v /etc/elastalert/config/config.json:/opt/elastalert-server/config/config.json \
  -v /etc/elastalert/rules:/opt/elastalert/rules \
  -v /etc/elastalert/rule_templates:/opt/elastalert/rule_templates \
  --net=host \
  bitsensor/elastalert:latest
