#!/bin/bash

# issues or renews a wildcard certificate obtained by the dns-rfc2136 challenge
# afterwards, reloads haproxy so that the cert can be used
# 
# cronjob:
# 10 6 * * * root <path to script>/renew.sh <domain> <mail> >/dev/null 2>&1

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 <domain> <mail>"
	exit 1
fi

SECONDS_DAY=86400
EXPIRY_DAYS=30
EXPIRY_SECONDS=$(( SECONDS_DAY * EXPIRY_DAYS ))

DOMAIN="$1"

# check if cert has to be renewed (expiring in less than EXPIRY_DAYS days)
if openssl x509 -checkend $EXPIRY_SECONDS -noout -in "/etc/ssl/private/$DOMAIN.pem"
then
	exit 0
fi

echo "Cert for $DOMAIN needs renewal"

certbot certonly \
	--force-renewal \
	--dns-rfc2136 \
	--dns-rfc2136-credentials /root/scripts/certbot-credentials.ini \
	--email "$2" \
	--agree-tos \
	--no-eff-email \
	-d "$DOMAIN" -d "*.$DOMAIN"

# create a concatenated cert file (required by haproxy)
cat "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/privkey.pem" > "/etc/ssl/private/$DOMAIN.pem"

# reload haproxy to apply new cert
systemctl reload haproxy