# Scry — CTF recon + LLM rating
FROM python:3.12-slim

LABEL org.opencontainers.image.title="scry" \
      org.opencontainers.image.description="Automated CTF recon: scan, find vulns, rate with Ollama"

# nmap + its NSE vuln scripts (nmap ships the 'vuln' script category)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# searchsploit / Exploit-DB for CVE enrichment. The exploit DB is large
# (~1 GB shallow clone); set INSTALL_SEARCHSPLOIT=false to build a lean image
# without offline exploit lookups. Update later inside the container: searchsploit -u
#
# The canonical gitlab.com/exploitdb/exploitdb repo now refuses anonymous
# clones, so we use the actively-maintained community mirror and fall back to
# the (older) GitHub mirror. GIT_TERMINAL_PROMPT=0 makes a bad URL fail fast
# instead of blocking on a credential prompt.
ARG INSTALL_SEARCHSPLOIT=true
RUN if [ "$INSTALL_SEARCHSPLOIT" = "true" ]; then \
        export GIT_TERMINAL_PROMPT=0 && \
        ( git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
          || git clone --depth 1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb ) && \
        ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
        searchsploit -j apache 2>/dev/null | grep -q '"EDB-ID"' ; \
    fi

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY scry ./scry
RUN pip install --no-cache-dir .

# Ollama runs as a separate service; point at it via env.
# docker-compose sets this to the 'ollama' service host.
ENV OLLAMA_HOST=http://ollama:11434 \
    OLLAMA_MODEL=llama3.1 \
    PYTHONUNBUFFERED=1

# Reports land here; mount a volume to keep them.
VOLUME ["/app/reports"]

ENTRYPOINT ["scry"]
CMD ["--help"]
