#!/usr/bin/env bash
docker-compose up -d
sleep 5
docker-compose exec --user postgres postgres createdb auth-manager
docker-compose exec ldap ldapadd -h localhost:389 -c -x -D cn=admin,dc=example,dc=com -w secret -f /data/users.ldif