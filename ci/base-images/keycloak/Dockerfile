# Équivalent local de quay.io/keycloak/keycloak:26.0 : distribution officielle 26.0.7 (sha1 vérifié) sur JRE 21.
FROM local/ubuntu:noble
ENV DEBIAN_FRONTEND=noninteractive LANG=en_US.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-21-jre-headless unzip \
 && rm -rf /var/lib/apt/lists/*
COPY keycloak-26.0.7.zip /tmp/kc.zip
RUN echo "c5e65ce1d609ef083089914bcf3660cfe800ed4e  /tmp/kc.zip" | sha1sum -c - \
 && unzip -q /tmp/kc.zip -d /opt && mv /opt/keycloak-26.0.7 /opt/keycloak && rm /tmp/kc.zip \
 && useradd -u 1000 -g 0 -M -d /opt/keycloak keycloak && chown -R 1000:0 /opt/keycloak && chmod -R g+rwX /opt/keycloak
USER 1000
EXPOSE 8080 8443 9000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
