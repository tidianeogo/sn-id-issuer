# Équivalent local de postgres:16 (même script d'entrée officiel docker-library/postgres),
# construit depuis les dépôts Ubuntu — utilisé quand les registres d'images sont inaccessibles.
FROM local/ubuntu:noble
ENV DEBIAN_FRONTEND=noninteractive PG_MAJOR=16 LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-16 gosu tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /docker-entrypoint-initdb.d /var/run/postgresql /var/lib/postgresql \
 && sed -ri "s!^#?(listen_addresses)\\s*=\\s*\\S+.*!\\1 = '*'!" /usr/share/postgresql/16/postgresql.conf.sample \
 && grep -F "listen_addresses = '*'" /usr/share/postgresql/16/postgresql.conf.sample \
 && chown -R postgres:postgres /var/run/postgresql /var/lib/postgresql && chmod 3777 /var/run/postgresql
ENV PATH=/usr/lib/postgresql/16/bin:$PATH PGDATA=/var/lib/postgresql/data
COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
STOPSIGNAL SIGINT
EXPOSE 5432
CMD ["postgres"]
