FROM python:3.13.13-slim-bookworm@sha256:355bfa66770995d7e9a0da4b3473b44d0cb451f6b56f5615ad9c39e3c4eca03f

RUN groupadd --gid 65532 dashboard \
    && useradd --uid 65532 --gid dashboard --no-create-home dashboard \
    && install -d -o dashboard -g dashboard /opt/lab-dashboard /var/lib/lab-dashboard

WORKDIR /opt/lab-dashboard
COPY --chown=dashboard:dashboard src/ ./src/
COPY --chown=dashboard:dashboard deploy/collector/ ./deploy/collector/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/lab-dashboard/src

USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["python", "-m", "lab_dashboard"]
