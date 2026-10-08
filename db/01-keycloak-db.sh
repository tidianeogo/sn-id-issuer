#!/bin/bash
# Crée la base et l'utilisateur dédiés à Keycloak dans la même instance PostgreSQL.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
  CREATE USER ${KC_DB_USER} WITH PASSWORD '${KC_DB_PASSWORD}';
  CREATE DATABASE ${KC_DB_NAME} OWNER ${KC_DB_USER};
SQL
