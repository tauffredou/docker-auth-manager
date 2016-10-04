#!/bin/bash
DOCKER=docker

export DOCKER_HOST=tcp://dockertest:2376
export DOCKER_TLS_VERIFY=1
export DOCKER_CERT_PATH=~/.docker/certs/server

SCRIPT_DIR=$(cd $(dirname $0);pwd)

openssl x509 -in $DOCKER_CERT_PATH/cert.pem -checkend 1
if [ $? = 1 ];then
  echo -n "username:"
  read USER
  echo -n "password:"
  read PASSWORD
set -x
  echo renew cert
  mkdir -p $DOCKER_CERTS_PATH
  curl -s 127.0.0.1:8080/api/domain/test/token --basic -u $USER:$PASSWORD | tar xz -C $DOCKER_CERT_PATH
fi

docker $@