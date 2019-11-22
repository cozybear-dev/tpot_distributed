#!/bin/bash

names=('cockpit' 'elastic' 'logstash' 'kibana' 'filebeat')
ip=('Unknown' '0.0.0.0' '0.0.0.0' 'Unknown' '0.0.0.0') #ONLY change Unknown and do not, I repeat, do not change the 0.0.0.0 IP's unless you know what you're doing

var=$((var=-1))

mkdir -p certs/rootCA

echo "You're about to generate your CA files - do this inside a secure environment and use a secure password that is stored safely and isolated."
openssl genrsa -des3 -out certs/rootCA/rootCA.key 4096
openssl req -x509 -new -nodes -key certs/rootCA/rootCA.key -sha256 -days 3650 -out certs/rootCA/rootCA.crt

for i in ${names[@]}; do
  var=$((var+1))
  mkdir certs/$i
  openssl genrsa -out certs/$i/$i.key 2048
  if [ $i == "elastic" ] || [ $i == "logstash" ] || [ $i == "filebeat" ]; then #ELk can not handle pkcs1 so convert to pkcs8
    echo ${ip[$var]}
    mv certs/$i/$i.key certs/$i/$i\1.key
    openssl pkcs8 -topk8 --inform PEM --outform PEM -in certs/$i/$i\1.key -out certs/$i/$i.key -nocrypt
  fi
  openssl req -new -sha256 -key certs/$i/$i.key -subj "/C=US/ST=CA/O=E-Corp, Inc./CN=${ip[$var]}" -out certs/$i/$i.csr #Change the -subj to your own needs
  openssl x509 -req -in certs/$i/$i.csr -CA certs/rootCA/rootCA.crt -CAkey certs/rootCA/rootCA.key -CAcreateserial -out certs/$i/$i.crt -days 3650 -sha256
  rm certs/$i/*1.key
done
