# syntax=docker/dockerfile:1

FROM python:3.12-alpine AS builder

WORKDIR /build

COPY requirements.txt .
# --target instead of a plain `pip install` so the runtime stage gets only
# the library files, not pip/setuptools/wheel and their own metadata.
# All deps (including cryptography's cffi extension) ship musllinux wheels,
# so this needs no compiler on the alpine builder either. --no-compile skips
# writing __pycache__/.pyc into the image (PYTHONDONTWRITEBYTECODE keeps the
# runtime stage from regenerating them); that's ~12MB of import-time bytecode
# cache traded for a negligible cold-start cost on a long-lived server.
RUN pip install --no-cache-dir --no-compile --target=/deps -r requirements.txt \
 && find /deps -name '__pycache__' -exec rm -rf {} +

# Everything below assembles the runtime filesystem but stays on a normal
# (layered) alpine base — Dockerfile RUN layers can only ever *add* data,
# so `rm -rf` here doesn't shrink the image, it just hides files that are
# still physically present in python:3.12-alpine's own layers underneath.
# The final `runtime` stage below flattens this stage's filesystem with a
# single COPY into a `scratch` base, which is what actually drops the
# deleted bytes from the pushed image.
FROM python:3.12-alpine AS prep

ENV PYTHONDONTWRITEBYTECODE=1

# No pip left to install arbitrary packages with at runtime — only the exact
# library files the builder stage resolved.
RUN python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true

# Stdlib pieces this headless HTTP server never touches: the GUI toolkit and
# its compiled extension, the source-to-source refactoring tool, the IDE,
# its demo, pydoc's HTML/text data, and ensurepip's bundled wheels (there's
# no pip left to bootstrap). Pinned to this alpine base's stdlib layout, so
# it needs re-checking on a base image bump.
RUN rm -rf \
      /usr/local/lib/python3.12/tkinter \
      /usr/local/lib/python3.12/lib-dynload/_tkinter*.so \
      /usr/local/lib/python3.12/lib2to3 \
      /usr/local/lib/python3.12/idlelib \
      /usr/local/lib/python3.12/turtledemo \
      /usr/local/lib/python3.12/turtle.py \
      /usr/local/lib/python3.12/pydoc_data \
      /usr/local/lib/python3.12/ensurepip

RUN addgroup -S app && adduser -S -G app -H -s /sbin/nologin app

WORKDIR /app
COPY --from=builder /deps /deps
COPY server.py oidc.py ./

# scratch has no base layers of its own, so copying `prep`'s current merged
# filesystem here — rather than stacking more layers on alpine directly —
# is what actually realizes the deletions above as reduced image size.
FROM scratch AS runtime

LABEL org.opencontainers.image.source="https://github.com/rikardronnkvist/tracearr-mcp-server" \
      org.opencontainers.image.licenses="MIT"

COPY --from=prep / /

# scratch starts with no image config of its own — PATH/LANG that
# python:3.12-alpine normally sets have to be restated here explicitly.
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

USER app

EXPOSE 8942

# Liveness only (process up, HTTP serving) — not Tracearr connectivity, so a
# transient Tracearr outage doesn't get Dockhand/Docker restarting this
# container in a loop. Use GET /ready separately to check Tracearr connectivity.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "\
import os, sys, urllib.request; \
port = os.environ.get('MCP_PORT', '8942'); \
sys.exit(0 if urllib.request.urlopen(f'http://localhost:{port}/health', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["python", "server.py"]
