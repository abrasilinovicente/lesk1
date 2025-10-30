#!/bin/bash
set -Eeuo pipefail
trap 'echo "[ERRO] linha $LINENO: $BASH_COMMAND (status $?)" >&2' ERR

echo "================================================= Verificação de permissão de root ================================================="

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

#================================================================================
# Script de Configuração Final (v3.0 - Com Cloudflare)
#================================================================================

# --- VALIDAÇÃO DOS ARGUMENTOS ---
if [ "$#" -ne 8 ]; then
    echo "ERRO: Número incorreto de argumentos. São necessários 8."
    echo "Recebidos: $#"
    echo "Argumentos: $@"
    exit 1
fi

# --- DEFINIÇÃO DE VARIÁVEIS A PARTIR DOS ARGUMENTOS ---
DOMAIN="$1"
URL_APP_ZIP="$2"
URL_ENVIO_ZIP="$3"
# $4 está vazio (reservado)
URL_OPENDKIM_CONF="$5"
URL_POSTFIX_CONF="$6"
CLOUDFLARE_API="$7"
CLOUDFLARE_EMAIL="$8"

# --- Obter IP público do servidor ---
SERVER_IP=$(wget -qO- http://ip-api.com/line?fields=query 2>/dev/null || echo "127.0.0.1")
PUBLIC_IP="${PUBLIC_IP:-$SERVER_IP}"   # <-- Corrigido para não gerar 'unbound variable'
echo "IP público detectado: ${PUBLIC_IP}"

# --- Domínio principal para Cloudflare ---
MAIN_DOMAIN=$(echo "$DOMAIN" | cut -d "." -f2-)

# Variáveis internas
WEB_ROOT="/var/www/html"
export DEBIAN_FRONTEND=noninteractive

# --- FUNÇÃO PARA LOG DE ERRO ---
log_error() {
    echo "!!-- ERRO CRÍTICO NA ETAPA: $1 --!!"
    exit 1
}

# --- INÍCIO DA CONFIGURAÇÃO ---
echo "🚀 Iniciando a configuração completa para o domínio: $DOMAIN"
echo "📧 Cloudflare Email: $CLOUDFLARE_EMAIL"
echo "🔑 Cloudflare API: ${CLOUDFLARE_API:0:10}..."
echo "🌐 Domínio principal: $MAIN_DOMAIN"
echo "📍 IP do servidor: $SERVER_IP"

# --- Atualização do sistema e pacotes essenciais ---
apt-get update && apt-get upgrade -y || log_error "Atualização do sistema"
apt-get install -y curl unzip software-properties-common toilet ufw jq || log_error "Pacotes essenciais"

# --- Configuração de hostname ---
hostnamectl set-hostname "$DOMAIN" && echo "$DOMAIN" > /etc/hostname || log_error "Configuração de Hostname"

# --- Firewall ---
ufw allow 'OpenSSH' && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 25/tcp && ufw --force enable || log_error "Configuração do Firewall"

# --- PHP & Apache ---
add-apt-repository ppa:ondrej/php -y && apt-get update -y || log_error "Repositório PHP"
apt-get install -y apache2 php7.4 libapache2-mod-php7.4 php7.4-cli php7.4-mysql php7.4-gd php7.4-imagick php7.4-tidy php7.4-xmlrpc php7.4-common php7.4-xml php7.4-curl php7.4-dev php7.4-imap php7.4-mbstring php7.4-opcache php7.4-soap php7.4-zip php7.4-intl --allow-unauthenticated || log_error "Apache e PHP"

# --- Certificado SSL ---
apt-get install -y certbot python3-certbot-apache || log_error "Certbot"
a2enmod rewrite ssl && systemctl restart apache2
certbot --apache --non-interactive --agree-tos -m "admin@$DOMAIN" -d "$DOMAIN" || log_error "SSL Certbot"

# ===================================================================
# DOWNLOAD E CONFIGURAÇÃO DO BACKEND
# ===================================================================
echo "-> Preparando para instalar aplicações..."
rm -f "$WEB_ROOT/index.html"

echo "-> Instalando Backend (API) no diretório home (/root/)..."
(
    cd /root/ && \
    echo "Baixando base.zip..." && \
    curl -L -o base.zip "$URL_APP_ZIP" && \
    echo "Extraindo base.zip..." && \
    unzip -o base.zip && \
    echo "Limpando base.zip..." && \
    rm base.zip
) || log_error "Instalação do Backend (API)"

echo "-> Aplicando permissões..."
chmod -R 777 "$WEB_ROOT"

# ===================================================================
# CONFIGURAÇÃO DE EMAIL (Postfix + OpenDKIM)
# ===================================================================
echo "-> Instalando e configurando servidor de email..."
(
    echo "postfix postfix/mailname string $DOMAIN" | debconf-set-selections
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
    apt-get install -y postfix opendkim opendkim-tools

    mkdir -p /etc/opendkim
    rm -f /etc/opendkim.conf
    wget -q -O /etc/opendkim.conf "$URL_OPENDKIM_CONF"

    echo "*@$DOMAIN default._domainkey.$DOMAIN" > /etc/opendkim/SigningTable
    echo "default._domainkey.$DOMAIN $DOMAIN:default:/etc/opendkim/keys/default.private" > /etc/opendkim/KeyTable
    echo -e "127.0.0.1\nlocalhost\n*.$DOMAIN" > /etc/opendkim/TrustedHosts

    chown -R opendkim:opendkim /etc/opendkim
    chmod go-rw /etc/opendkim

    mkdir -p /etc/opendkim/keys
    (cd /etc/opendkim/keys && opendkim-genkey -s default -d "$DOMAIN")
    chown opendkim:opendkim /etc/opendkim/keys/default.private
    chmod 600 /etc/opendkim/keys/default.private

    adduser postfix opendkim

    rm -f /etc/postfix/main.cf
    wget -q -O /etc/postfix/main.cf "$URL_POSTFIX_CONF"
    sed -i "s/seudominio.com/$DOMAIN/g" /etc/postfix/main.cf

    echo "www-data ALL=(ALL) NOPASSWD: /usr/sbin/postsuper" | tee -a /etc/sudoers > /dev/null

    systemctl restart opendkim
    systemctl reload postfix
) || log_error "Configuração do Servidor de Email"

# ===================================================================
# CONFIGURAÇÃO DE LOGGING DE EMAIL
# ===================================================================
echo "-> Configurando logging de email..."
(
    if ! command -v rsyslogd >/dev/null 2>&1; then
        echo "-> Instalando rsyslog..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog
        systemctl enable rsyslog
        systemctl start rsyslog
    fi

    touch /var/log/maillog /var/log/mail.info /var/log/mail.warn /var/log/mail.err
    chmod 640 /var/log/maillog /var/log/mail.*
    chown root:root /var/log/maillog /var/log/mail.*

    if [ -f /etc/rsyslog.conf ]; then
        if ! grep -q "mail.*" /etc/rsyslog.conf; then
            echo "mail.*                          /var/log/maillog" >> /etc/rsyslog.conf
        fi
        systemctl restart rsyslog 2>/dev/null || true
    fi
) || echo "⚠️ Problema na configuração de logging (não crítico)"

# ===================================================================
# CONFIGURAÇÃO CLOUDFLARE DNS (DKIM)
# ===================================================================
if [ -n "${CLOUDFLARE_API}" ] && [ -n "${CLOUDFLARE_EMAIL}" ]; then
    echo "-> Configurando DNS no Cloudflare..."

    DKIM_FILE="/etc/opendkim/keys/default.txt"

    # Extrair chave DKIM
    DKIMCode=$(grep -v "^default._domainkey" "$DKIM_FILE" | \
               sed 's/^[[:space:]]*"//' | \
               sed 's/"[[:space:]]*).*//' | \
               sed 's/"$//' | \
               tr -d '\n \t')
    DKIMCode=$(echo "$DKIMCode" | sed 's/^v=DKIM1;[^p]*p=//' | sed 's/^p=//')
    DKIMCode=$(echo "$DKIMCode" | sed 's/[^A-Za-z0-9+\/=]//g')

    if [ ${#DKIMCode} -lt 300 ]; then
        echo "❌ ERRO: Chave DKIM muito curta, verifique o arquivo $DKIM_FILE"
    else
        echo "-> Chave DKIM extraída, criando registro DNS via API Cloudflare..."
        CLOUDFLARE_ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$MAIN_DOMAIN" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API" \
            -H "Content-Type: application/json" | jq -r '.result[0].id')

        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"TXT\",\"name\":\"default._domainkey.$DOMAIN\",\"content\":\"v=DKIM1; k=rsa; p=$DKIMCode\",\"ttl\":3600,\"proxied\":false}"
    fi
fi

# ===================================================================
# FINALIZAÇÃO
# ===================================================================
echo "✅ Configuração concluída para $DOMAIN"
echo "📌 IP do servidor: $SERVER_IP"
echo "📌 IP público: $PUBLIC_IP"
echo "📌 SSL e Apache configurados"
echo "📌 Servidor de email Postfix + OpenDKIM pronto"
echo "📌 DNS DKIM configurado no Cloudflare (se credenciais informadas)"

