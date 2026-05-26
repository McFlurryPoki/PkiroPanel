FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Pre-downloaded binaries (for CN mirror) ────────────────────────────────
# These are built into the image; update them by re-downloading and rebuilding.
COPY agent/bin/ /app/agent/bin/

COPY panel/ ./panel/
COPY agent/ ./agent/
COPY install.sh .
COPY install-cn.sh .
COPY uninstall.sh .

RUN mkdir -p /data

ENV PANEL_PORT=32100
ENV DB_PATH=/data/realm_panel.db
ENV SECRET_KEY=change-me-in-production
ENV PANEL_URL=http://localhost:32100

EXPOSE 32100

CMD ["python", "-m", "uvicorn", "panel.main:app", "--host", "0.0.0.0", "--port", "32100"]
