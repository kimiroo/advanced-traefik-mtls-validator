FROM python:3.13-alpine

ENV HOST=0.0.0.0
ENV PORT=18000

COPY . /app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
WORKDIR /app

RUN chmod +x /usr/local/bin/entrypoint.sh
RUN apk add --no-cache build-base libffi-dev openssl-dev python3-dev curl
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN apk del build-base libffi-dev openssl-dev python3-dev
RUN rm -rf /var/cache/apk/*

EXPOSE $PORT

HEALTHCHECK --interval=5s --timeout=3s CMD curl -f http://127.0.0.1:$PORT/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["-w", "1", "app:app"]