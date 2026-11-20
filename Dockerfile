# morfPhoto : image autonome (ExifTool et pilote SQLite inclus).
# SPDX-License-Identifier: GPL-3.0-only

FROM debian:trixie-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake ninja-build g++ qt6-base-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Seule la cible du service : le helper setuid (montages SMB) n'a pas sa place ici.
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /build --target morfphoto

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libqt6core6t64 libqt6network6 libqt6sql6 libqt6sql6-sqlite libqt6concurrent6 \
        libimage-exiftool-perl curl ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
COPY docker/clip/requirements.txt /tmp/clip-requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && python3 -m venv /opt/morfphoto-clip \
    && /opt/morfphoto-clip/bin/pip install --no-cache-dir -r /tmp/clip-requirements.txt \
    && rm -rf /var/lib/apt/lists/* /tmp/clip-requirements.txt
COPY docker/clip/*.py /opt/morfphoto-clip/
COPY --from=build /build/service/morfphoto /usr/local/bin/morfphoto
COPY docker/morfphoto.json /etc/morfsystem/morfphoto/morfphoto.json
COPY docker/entrypoint.sh /usr/local/bin/morfphoto-entrypoint
RUN chmod 0755 /usr/local/bin/morfphoto-entrypoint && mkdir -p /data /photos

# Paths::stateDir lit cette variable : la base vit sur le volume, sans changer le code.
ENV STATE_DIRECTORY=/data
VOLUME /data
EXPOSE 8793
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD curl -fsS http://127.0.0.1:8793/healthz >/dev/null || exit 1

# tini en PID 1 : le service ne gere pas SIGTERM, qu'un PID 1 ignorerait sinon.
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/local/bin/morfphoto-entrypoint"]
CMD ["/usr/local/bin/morfphoto", "--config", "/etc/morfsystem/morfphoto/morfphoto.json"]
