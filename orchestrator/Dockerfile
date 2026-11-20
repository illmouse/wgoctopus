FROM python:3.12-slim AS build
WORKDIR /build
COPY orchestrator/pyproject.toml ./orchestrator/pyproject.toml
COPY orchestrator/src ./orchestrator/src
COPY orchestrator/migrations ./orchestrator/migrations
COPY orchestrator/alembic.ini ./orchestrator/alembic.ini
RUN pip install --no-cache-dir --prefix=/install ./orchestrator

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 WGOCTOPUS_API_HOST=0.0.0.0 WGOCTOPUS_DATABASE_URL=sqlite:////var/lib/wgoctopus/orchestrator.db WGOCTOPUS_SCHEMA_PATH=/app/schema/state.schema.json WGOCTOPUS_MIGRATIONS_PATH=/app/migrations WGOCTOPUS_ALEMBIC_CONFIG=/app/alembic.ini
COPY --from=build /install /usr/local
COPY schema/state.schema.json /app/schema/state.schema.json
COPY orchestrator/migrations /app/migrations
COPY orchestrator/alembic.ini /app/alembic.ini
RUN useradd --uid 10001 --create-home orch && mkdir -p /var/lib/wgoctopus && chown 10001:10001 /var/lib/wgoctopus
USER 10001
VOLUME /var/lib/wgoctopus
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2)"
CMD ["python", "-m", "wgoctopus_orch"]
