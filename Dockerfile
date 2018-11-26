FROM certbot/certbot

COPY . src/certbot-dns-rrpproxy

RUN pip install --no-cache-dir --editable src/certbot-dns-rrpproxy
