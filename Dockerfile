FROM python:3.12-alpine

RUN adduser -D -u 10001 app && mkdir /data && chown app /data
WORKDIR /app
COPY app.py .

USER app
ENV OUT_DIR=/data PORT=8080 REFRESH_HOURS=24
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"

CMD ["python", "-u", "app.py"]
