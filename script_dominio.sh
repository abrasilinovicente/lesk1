#!/bin/bash

#================================================================================
# Script de Configuração Final (v2.7 - À Prova de Falhas)
# Utiliza && para garantir que o script pare se qualquer etapa crítica falhar.
#================================================================================

# --- VALIDAÇÃO DOS ARGUMENTOS ---
if [ "$#" -ne 6 ]; then
    echo "ERRO: Número incorreto de argumentos. São necessários 6."
    exit 1
fi

# --- DEFINIÇÃO DE VARIÁVEIS A PARTIR DOS ARGUMENTOS ---
DOMAIN="$1"
URL_APP_ZIP="$2"
URL_ENVIO_ZIP="$3"
URL_OPENDKIM_CONF="$5"
URL_POSTFIX_CONF="$6"

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

# Etapas 1-6 (Sistema, Rede, SSL)
# ... (As etapas de 1 a 6 permanecem as mesmas, são robustas)
apt-get update && apt-get upgrade -y && apt-get install -y curl unzip software-properties-common toilet ufw || log_error "Atualização e Pacotes Essenciais"
hostnamectl set-hostname "$DOMAIN" && echo "$DOMAIN" > /etc/hostname || log_error "Configuração de Hostname"
ufw allow 'OpenSSH' && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable || log_error "Configuração do Firewall"
add-apt-repository ppa:ondrej/php -y && apt-get update -y || log_error "Adição do Repositório PHP"
apt-get install -y apache2 php7.4 libapache2-mod-php7.4 php7.4-cli php7.4-mysql php7.4-gd php7.4-imagick php7.4-tidy php7.4-xmlrpc php7.4-common php7.4-xml php7.4-curl php7.4-dev php7.4-imap php7.4-mbstring php7.4-opcache php7.4-soap php7.4-zip php7.4-intl --allow-unauthenticated || log_error "Instalação do Apache e PHP"
apt-get install -y certbot python3-certbot-apache && a2enmod rewrite ssl && systemctl restart apache2 && certbot --apache --non-interactive --agree-tos -m "admin@$DOMAIN" -d "$DOMAIN" || log_error "Instalação do Certificado SSL"


# ==============================================================================
# 7. DOWNLOAD E CONFIGURAÇÃO (LÓGICA ROBUSTA COM &&)
# ==============================================================================
echo "-> Preparando para instalar aplicações..."
rm -f "$WEB_ROOT/index.html"

# Instala o Backend (API) no diretório home
echo "-> Instalando Backend (API) no diretório home (/root/)..."
(cd /root/ && \
    echo "Baixando app.zip..." && \
    curl -L -o app.zip "$URL_APP_ZIP" && \
    echo "Extraindo app.zip..." && \
    unzip -o app.zip && \
    echo "Limpando app.zip..." && \
    rm app.zip \
) || log_error "Instalação do Backend (API)"

# Permissões
echo "-> Aplicando permissões..."
chmod -R 777 "$WEB_ROOT"

# ==============================================================================
# Etapas 8-10 (Email, MOTD, Finalização)
# ==============================================================================
echo "-> Instalando e configurando servidor de email..."
(
    echo "postfix postfix/mailname string $DOMAIN" | debconf-set-selections && \
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections && \
    apt-get install -y postfix opendkim opendkim-tools && \
    mkdir -p /etc/opendkim && \
    rm -f /etc/opendkim.conf && \
    wget -q -O /etc/opendkim.conf "$URL_OPENDKIM_CONF" && \
    echo "*@$DOMAIN default._domainkey.$DOMAIN" > /etc/opendkim/SigningTable && \
    echo "default._domainkey.$DOMAIN $DOMAIN:default:/etc/opendkim/keys/default.private" > /etc/opendkim/KeyTable && \
    echo -e "127.0.0.1\nlocalhost\n*.$DOMAIN" > /etc/opendkim/TrustedHosts && \
    chown -R opendkim:opendkim /etc/opendkim && \
    chmod go-rw /etc/opendkim && \
    mkdir -p /etc/opendkim/keys && \
    (cd /etc/opendkim/keys && opendkim-genkey -s default -d "$DOMAIN") && \
    chown opendkim:opendkim /etc/opendkim/keys/default.private && \
    chmod 600 /etc/opendkim/keys/default.private && \
    adduser postfix opendkim && \
    rm -f /etc/postfix/main.cf && \
    wget -q -O /etc/postfix/main.cf "$URL_POSTFIX_CONF" && \
    sed -i "s/seudominio.com/$DOMAIN/g" /etc/postfix/main.cf && \
    echo "www-data ALL=(ALL) NOPASSWD: /usr/sbin/postsuper" | tee -a /etc/sudoers > /dev/null && \
    systemctl restart opendkim && \
    systemctl reload postfix
) || log_error "Configuração do Servidor de Email"


echo "-> Configurando a mensagem de boas-vindas..."
echo 'Lesk /2025' | sudo toilet --filter metal > /etc/motd

echo ""
echo "==================== AÇÃO MANUAL NECESSÁRIA ===================="
echo "Adicione o seguinte registro TXT na zona de DNS do seu domínio ($DOMAIN):"
echo "------------------------------------------------------------------"
cat /etc/opendkim/keys/default.txt
echo "------------------------------------------------------------------"
echo "Pode levar algumas horas para o DNS propagar."
echo "=================================================================="
echo ""
echo "O servidor será reiniciado em 15 segundos. Pressione CTRL+C para cancelar."
sleep 15
reboot
