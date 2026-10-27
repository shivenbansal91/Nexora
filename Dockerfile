# ─────────────────────────────────────────────────────────────────────────────
# Nexora — single-image build.
#   Stage 1 builds the React frontend.
#   Stage 2 installs the Python backend, trains the detection models, copies the
#   built frontend in, and serves everything (SPA + REST + WebSocket) on :8000.
# ─────────────────────────────────────────────────────────────────────────────

# ---- Stage 1: frontend ----
FROM node:22-alpine AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: backend ----
FROM python:3.12-slim AS app
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app:/app/p2-pipeline

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY backend/ ./backend/
COPY correlation/ ./correlation/
COPY detection/ ./detection/
COPY p2-pipeline/ ./p2-pipeline/
COPY data/ ./data/

# Built SPA from stage 1
COPY --from=frontend /fe/dist ./frontend/dist

# Train detection models + write metrics at build time so the image is ready.
RUN python -m detection.train_baseline

RUN useradd --create-home nexora && chown -R nexora:nexora /app
USER nexora

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"

EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
