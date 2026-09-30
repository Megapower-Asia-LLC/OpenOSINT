FROM python:3.11-slim

WORKDIR /app

# libicu-dev + a compiler are needed once, to build PyICU (required by the
# graph view's followthemoney dependency); the compiler is purged afterwards.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential pkg-config libicu-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Editable on purpose: /api/setup saves keys to <package root>/.env, which
# must resolve to /app/.env (see the CMD below).
RUN pip install --no-cache-dir -e ".[graph]" \
    && apt-get purge -y --auto-remove build-essential pkg-config

# Optional OSINT binaries available via pip
RUN pip install --no-cache-dir holehe sherlock-project sublist3r

RUN mkdir -p /app/reports /data

# graph.db and session history live here; mount a volume to persist them.
ENV OPENOSINT_HOME=/data
VOLUME /data

EXPOSE 8080

# --allow-remote is required for a non-loopback bind (GHSA-cqr4-hcfp-m6m4) —
# safe here because the container network boundary is what's actually
# exposed; publish the port only to trusted networks.
# /app/.env is a symlink into the data volume so keys saved from the UI
# survive container re-creation without a bind-mounted file.
CMD ["sh", "-c", "touch /data/.env && ln -sf /data/.env /app/.env && exec openosint web --host 0.0.0.0 --port 8080 --no-browser --allow-remote"]
