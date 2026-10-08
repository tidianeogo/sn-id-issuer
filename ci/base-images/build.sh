#!/bin/bash
# Reconstruit, sans aucun registre d'images, des équivalents des 3 images de base utilisées par
# docker-compose.yml, et les étiquette sous les mêmes noms. Prérequis : accès à archive.ubuntu.com
# (debootstrap) et à github.com (distribution Keycloak + script d'entrée Postgres).
set -euo pipefail
cd "$(dirname "$0")"
ROOTFS=${ROOTFS:-/var/tmp/rootfs}
if ! docker image inspect local/ubuntu:noble >/dev/null 2>&1; then
  [ -d "$ROOTFS/usr" ] || sudo debootstrap --variant=minbase --include=ca-certificates noble "$ROOTFS" http://archive.ubuntu.com/ubuntu/
  printf 'deb http://archive.ubuntu.com/ubuntu noble main universe\ndeb http://archive.ubuntu.com/ubuntu noble-updates main universe\ndeb http://security.ubuntu.com/ubuntu noble-security main universe\n' | sudo tee "$ROOTFS/etc/apt/sources.list" >/dev/null
  sudo tar -C "$ROOTFS" -c . | docker import - local/ubuntu:noble
fi
[ -f keycloak/keycloak-26.0.7.zip ] || curl -fSL -o keycloak/keycloak-26.0.7.zip \
  https://github.com/keycloak/keycloak/releases/download/26.0.7/keycloak-26.0.7.zip
docker build --network host -t postgres:16-alpine postgres
docker build --network host -t quay.io/keycloak/keycloak:26.0 keycloak
docker build --network host -t python:3.12-slim python
docker build --network host -t nginx:1.27-alpine nginx
echo "Images de base prêtes."
