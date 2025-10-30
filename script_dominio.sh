#!/bin/bash
set -Eeuo pipefail
trap 'echo "[ERRO] linha $LINENO: $BASH_COMMAND (status $?)" >&2' ERR
[ "$(id -u)" -ne 0 ] && { echo "❌ Execute como root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

DOMAIN="${1:-}"; URL_OPENDKIM_CONF="${2:-}"; CLOUDFLARE_API="${3:-}"; CLOUDFLARE_EMAIL="${4:-}"
[ -z "$DOMAIN" ] && { echo "Uso: $0 <DOMÍNIO> [URL_OPENDKIM_CONF] [CLOUDFLARE_API] [CLOUDFLARE_EMAIL]"; exit 1; }

PUBLIC_IP=$(curl -s ifconfig.me || wget -qO- ifconfig.me)
HOSTNAME="mail.$DOMAIN"

echo "📦 Instalando dependências..."
apt-get update -qq && apt-get install -y postfix dovecot-core dovecot-imapd opendkim opendkim-tools \
certbot python3-certbot-nginx nginx ufw jq unzip curl wget toilet > /dev/null

hostnamectl set-hostname "$HOSTNAME"
ufw allow OpenSSH && ufw allow 25,80,143,443,465,587,993/tcp && ufw --force enable

echo "⚙️ Configurando OpenDKIM..."
mkdir -p /etc/opendkim/keys
cat > /etc/opendkim.conf <<EOF
Syslog yes
UMask 002
Domain *
KeyFile /etc/opendkim/keys/default.private
Selector default
Socket inet:12301@localhost
Canonicalization relaxed/simple
Mode sv
SubDomains no
AutoRestart yes
EOF
[ ! -f /etc/opendkim/keys/default.private ] && {
  opendkim-genkey -D /etc/opendkim/ -d "$DOMAIN" -s default
  mv /etc/opendkim/default.private /etc/opendkim/keys/default.private
  mv /etc/opendkim/default.txt /etc/opendkim/keys/default.txt
}
chown -R opendkim:opendkim /etc/opendkim && chmod go-rw /etc/opendkim/keys/default.private
echo 'SOCKET="inet:12301@localhost"' > /etc/default/opendkim

echo "📧 Configurando Postfix..."
mkdir -p /etc/postfix
cat > /etc/postfix/main.cf <<EOF
myhostname = $HOSTNAME
mydomain = $DOMAIN
myorigin = /etc/mailname
mydestination = localhost, \$myhostname, \$mydomain
mynetworks = 127.0.0.0/8
inet_interfaces = all
inet_protocols = all
home_mailbox = Maildir/
smtp_tls_cert_file=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
smtp_tls_key_file=/etc/letsencrypt/live/$DOMAIN/privkey.pem
smtp_use_tls=yes
smtpd_use_tls=yes
milter_default_action = accept
milter_protocol = 2
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301
EOF

echo "💾 Configurando Dovecot..."
cat > /etc/dovecot/dovecot.conf <<EOF
protocols = imap
listen = *
mail_location = maildir:~/Maildir
ssl = required
ssl_cert = </etc/letsencrypt/live/$DOMAIN/fullchain.pem
ssl_key = </etc/letsencrypt/live/$DOMAIN/privkey.pem
disable_plaintext_auth = yes
auth_mechanisms = plain login
passdb { driver = pam }
userdb { driver = passwd }
EOF

echo "🔐 Certificados SSL Let's Encrypt..."
certbot certonly --nginx -d "$DOMAIN" -d "mail.$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" || true

echo "🌐 Configurando Nginx..."
cat > /etc/nginx/sites-available/mail.conf <<EOF
server { listen 80; server_name mail.$DOMAIN $PUBLIC_IP; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl;
    server_name mail.$DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    root /var/www/html; index index.html;
}
EOF
ln -sf /etc/nginx/sites-available/mail.conf /etc/nginx/sites-enabled/mail.conf
nginx -t && systemctl reload nginx

if [[ -n "$CLOUDFLARE_API" && -n "$CLOUDFLARE_EMAIL" ]]; then
  echo "☁️ Configurando Cloudflare DNS..."
  ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
    -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "X-Auth-Key: $CLOUDFLARE_API" \
    -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
  [ -n "$ZONE_ID" ] && [ "$ZONE_ID" != "null" ] && {
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
      -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "X-Auth-Key: $CLOUDFLARE_API" \
      -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"mail.$DOMAIN\",\"content\":\"$PUBLIC_IP\",\"ttl\":120,\"proxied\":false}" >/dev/null
    echo "✅ DNS criado com sucesso!"
  } || echo "⚠️ Falha ao obter Zone ID."
else
  echo "⚠️ Cloudflare não configurado (sem API/EMAIL)."
fi

echo "🔄 Reiniciando serviços..."
systemctl daemon-reload
systemctl enable opendkim postfix dovecot nginx
systemctl restart opendkim postfix dovecot nginx

echo 'Lesk /2025' | toilet --filter metal > /etc/motd
echo "🎉 Instalação concluída!"
echo "Domínio: $DOMAIN"
echo "SSL ativo, DKIM gerado e DNS configurado (se aplicável)."
echo "Reiniciando servidor em 15s..."
sleep 15 && reboot
