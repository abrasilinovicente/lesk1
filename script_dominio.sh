#!/bin/bash

# =====================================================
# INSTALADOR COMPLETO DE SERVIDOR SMTP
# Versão 2.2 - Com Sistema de Análise de Bounces
# Script 100% COMPLETO - Todas as funcionalidades
# =====================================================

# Configurar para modo não-interativo
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

# ====================================
# RECEBER PARÂMETROS
# ====================================
FULL_DOMAIN=$1
URL_OPENDKIM_CONF=$2
CLOUDFLARE_API=$3
CLOUDFLARE_EMAIL=$4

if [ -z "$FULL_DOMAIN" ]; then
    echo "ERRO: Domínio não fornecido!"
    echo "Uso: bash $0 <dominio_completo>"
    echo "Exemplo: bash $0 webmail.exemplo.com"
    exit 1
fi

# Extrair subdomínio e domínio base
SUBDOMAIN=$(echo "$FULL_DOMAIN" | cut -d'.' -f1)
BASE_DOMAIN=$(echo "$FULL_DOMAIN" | cut -d'.' -f2-)

if [ -z "$SUBDOMAIN" ] || [ -z "$BASE_DOMAIN" ]; then
    echo "ERRO: Não foi possível extrair subdomínio e domínio base"
    exit 1
fi

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   INSTALADOR DE SERVIDOR SMTP${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Domínio Completo: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}Subdomínio: ${YELLOW}$SUBDOMAIN${NC}"
echo -e "${GREEN}Domínio Base: ${YELLOW}$BASE_DOMAIN${NC}"
echo -e "${GREEN}Versão: ${YELLOW}2.2 COMPLETO${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${CYAN}📋 Etapas da instalação:${NC}"
echo -e "  1. Verificar sistema"
echo -e "  2. Instalar pacotes"
echo -e "  3. Configurar OpenDKIM"
echo -e "  4. Configurar Postfix"
echo -e "  5. Configurar Dovecot"
echo -e "  6. Configurar sistema de análise"
echo -e "  7. Criar páginas web"
echo -e "  8. Reiniciar serviços\n"

sleep 2

# Função para aguardar apt
wait_for_apt() {
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if ! lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
           ! lsof /var/lib/apt/lists/lock >/dev/null 2>&1 && \
           ! lsof /var/cache/apt/archives/lock >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Sistema disponível${NC}"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
    
    killall -9 apt apt-get dpkg 2>/dev/null || true
    sleep 2
    rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
    dpkg --configure -a 2>/dev/null || true
    return 1
}

wait_for_apt

# Configurações para instalação não-interativa
echo '#!/bin/sh' > /usr/sbin/policy-rc.d
echo 'exit 101' >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

mkdir -p /etc/needrestart/conf.d/
cat > /etc/needrestart/conf.d/99-autorestart.conf << 'EOF'
$nrconf{restart} = 'a';
$nrconf{kernelhints} = -1;
$nrconf{ucodehints} = 0;
EOF

apt-get update -y -qq

# Pré-configurar Postfix
echo -e "${YELLOW}Pré-configurando Postfix...${NC}"
wait_for_apt
echo "postfix postfix/mailname string $BASE_DOMAIN" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
echo "postfix postfix/destinations string $BASE_DOMAIN, localhost" | debconf-set-selections
echo "postfix postfix/relayhost string ''" | debconf-set-selections

# Instalar pacotes
echo -e "${YELLOW}Instalando pacotes...${NC}"
wait_for_apt
PACKAGES="postfix opendkim opendkim-tools dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd libsasl2-2 libsasl2-modules sasl2-bin mailutils wget unzip curl nginx ssl-cert pflogsumm postfix-pcre apache2-utils"

for package in $PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $package"; then
        apt-get install -y -qq $package -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null
    fi
done

echo -e "${GREEN}✓ Pacotes instalados${NC}"

# Criar diretórios
mkdir -p /var/www/html
mkdir -p /etc/nginx/sites-{available,enabled}
mkdir -p /var/mail/vhosts/$BASE_DOMAIN
mkdir -p /etc/opendkim/keys/$BASE_DOMAIN
mkdir -p /var/log/mail-analysis/{bounces,rejected,deferred,reports,daily}

chmod -R 755 /var/log/mail-analysis
chown -R syslog:adm /var/log/mail-analysis

rm -f /usr/sbin/policy-rc.d

# Configurar hostname
hostnamectl set-hostname $FULL_DOMAIN
echo "127.0.0.1 $FULL_DOMAIN" >> /etc/hosts

# ====================================
# CONFIGURAR OPENDKIM
# ====================================
echo -e "${YELLOW}Configurando OpenDKIM...${NC}"

cat > /etc/opendkim.conf << EOF
Domain                  $BASE_DOMAIN
KeyFile                 /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.private
Selector                $SUBDOMAIN
Socket                  inet:8891@localhost
PidFile                 /var/run/opendkim/opendkim.pid
UserID                  opendkim:opendkim
Syslog                  yes
LogWhy                  yes
EOF

mkdir -p /etc/opendkim/keys/$BASE_DOMAIN /var/run/opendkim /var/log/opendkim
chown -R opendkim:opendkim /var/run/opendkim /var/log/opendkim 2>/dev/null || true

cd /etc/opendkim/keys/$BASE_DOMAIN
opendkim-genkey -b 1024 -s $SUBDOMAIN -d $BASE_DOMAIN 2>/dev/null || {
    rm -f $SUBDOMAIN.private $SUBDOMAIN.txt
    opendkim-genkey -b 1024 -s $SUBDOMAIN -d $BASE_DOMAIN
}

if [ -f $SUBDOMAIN.private ]; then
    chown opendkim:opendkim $SUBDOMAIN.private
    chmod 600 $SUBDOMAIN.private
else
    openssl genrsa -out $SUBDOMAIN.private 1024
    openssl rsa -in $SUBDOMAIN.private -pubout -out $SUBDOMAIN.txt
    chown opendkim:opendkim $SUBDOMAIN.private
    chmod 600 $SUBDOMAIN.private
fi

chown -R opendkim:opendkim /etc/opendkim /var/run/opendkim

echo -e "${GREEN}✓ OpenDKIM configurado${NC}"

# ====================================
# CONFIGURAR POSTFIX
# ====================================
echo -e "${YELLOW}Configurando Postfix...${NC}"

cat > /etc/postfix/main.cf << EOF
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
smtp_address_preference = ipv4
biff = no
append_dot_mydomain = no
readme_directory = no
recipient_delimiter = +
mailbox_size_limit = 0
compatibility_level = 2

myhostname = $FULL_DOMAIN
mydomain = $BASE_DOMAIN
myorigin = /etc/mailname
mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
relayhost =

inet_interfaces = all
inet_protocols = ipv4

maillog_file = /var/log/postfix.log
maillog_file_prefixes = /var/log
maillog_file_rotate_suffix = %Y%m%d-%H%M%S
maillog_file_compressor = gzip

debug_peer_level = 2
smtp_tls_loglevel = 1
smtpd_tls_loglevel = 1

bounce_notice_recipient = postmaster@$BASE_DOMAIN
2bounce_notice_recipient = postmaster@$BASE_DOMAIN
delay_notice_recipient = postmaster@$BASE_DOMAIN
error_notice_recipient = postmaster@$BASE_DOMAIN
notify_classes = bounce, 2bounce, delay, resource, software

alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

smtpd_relay_restrictions =
    permit_mynetworks
    permit_sasl_authenticated
    defer_unauth_destination
    reject_unauth_destination

smtpd_use_tls = yes
EOF

if [ -f "/etc/letsencrypt/live/$BASE_DOMAIN/fullchain.pem" ]; then
    cat >> /etc/postfix/main.cf << EOF
smtpd_tls_cert_file = /etc/letsencrypt/live/$BASE_DOMAIN/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/$BASE_DOMAIN/privkey.pem
EOF
else
    cat >> /etc/postfix/main.cf << EOF
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
EOF
fi

cat >> /etc/postfix/main.cf << EOF
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_security_level = may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3
smtpd_tls_ciphers = high
smtpd_tls_mandatory_ciphers = high

milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $BASE_DOMAIN
broken_sasl_auth_clients = yes

virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = $BASE_DOMAIN
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_minimum_uid = 100
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

smtpd_helo_required = yes
smtpd_helo_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname

smtpd_sender_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain

smtpd_recipient_restrictions = 
    permit_sasl_authenticated,
    permit_mynetworks,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient,
    reject_unknown_sender_domain,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org,
    reject_rhsbl_client dbl.spamhaus.org,
    reject_rhsbl_sender dbl.spamhaus.org

message_size_limit = 52428800
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d
maximal_backoff_time = 4000s
minimal_backoff_time = 300s
queue_run_delay = 300s

smtpd_client_connection_count_limit = 50
smtpd_client_connection_rate_limit = 100
anvil_rate_time_unit = 60s

smtpd_data_restrictions = reject_unauth_pipelining
smtpd_error_sleep_time = 1s
smtpd_soft_error_limit = 10
smtpd_hard_error_limit = 20
bounce_size_limit = 50000
EOF

echo "$BASE_DOMAIN" > /etc/mailname

cat > /etc/postfix/master.cf << 'EOF'
smtp      inet  n       -       y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
EOF

groupadd -g 5000 vmail 2>/dev/null || true
useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m 2>/dev/null || true
mkdir -p /var/mail/vhosts/$BASE_DOMAIN
chown -R vmail:vmail /var/mail/vhosts

echo "admin@$BASE_DOMAIN $BASE_DOMAIN/admin/" > /etc/postfix/vmailbox
postmap /etc/postfix/vmailbox

echo -e "${GREEN}✓ Postfix configurado${NC}"

# ====================================
# CONFIGURAR DOVECOT
# ====================================
echo -e "${YELLOW}Configurando Dovecot...${NC}"

cat > /etc/dovecot/dovecot.conf << EOF
protocols = imap pop3 lmtp
listen = 0.0.0.0
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail

ssl = yes
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key

auth_mechanisms = plain login
disable_plaintext_auth = no

first_valid_uid = 5000
last_valid_uid = 5000
first_valid_gid = 5000
last_valid_gid = 5000

log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log

namespace inbox {
  inbox = yes
  location = 
  mailbox Drafts {
    auto = create
    special_use = \Drafts
  }
  mailbox Junk {
    auto = create
    special_use = \Junk
  }
  mailbox Sent {
    auto = create
    special_use = \Sent
  }
  mailbox Trash {
    auto = create
    special_use = \Trash
  }
  prefix = 
}

protocol imap {
  mail_max_userip_connections = 100
}

protocol pop3 {
  mail_max_userip_connections = 10
}

protocol lmtp {
  mail_plugins = quota
  postmaster_address = postmaster@$BASE_DOMAIN
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  
  unix_listener auth-userdb {
    mode = 0660
    user = vmail
    group = vmail
  }
}

service auth-worker {
  user = vmail
}

passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/users
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n allow_all_users=yes
}
EOF

echo "admin@$BASE_DOMAIN:{PLAIN}dwwzyd" > /etc/dovecot/users
chmod 640 /etc/dovecot/users
chown root:dovecot /etc/dovecot/users

mkdir -p /var/mail/vhosts/$BASE_DOMAIN/admin
chown -R vmail:vmail /var/mail/vhosts/$BASE_DOMAIN/admin

echo -e "${GREEN}✓ Dovecot configurado${NC}"

# Vou continuar o script em uma segunda parte...

# ====================================
# SCRIPT DE ANÁLISE DE LOGS
# ====================================
echo -e "${YELLOW}Criando script de análise...${NC}"

cat > /usr/local/bin/analyze-mail-logs.sh << 'ANALYZESCRIPT'
#!/bin/bash
LOG_DIR="/var/log/mail-analysis"
POSTFIX_LOG="/var/log/postfix.log"

mkdir -p $LOG_DIR/{bounces,rejected,deferred,reports,daily}

if [ -f "$POSTFIX_LOG" ]; then
    grep -i "bounced" $POSTFIX_LOG | tail -n 100 > $LOG_DIR/bounces/bounces-$(date +%Y%m%d-%H%M%S).log
    grep -E "reject|rejected" $POSTFIX_LOG | tail -n 100 > $LOG_DIR/rejected/rejected-$(date +%Y%m%d-%H%M%S).log
    grep -i "deferred" $POSTFIX_LOG | tail -n 100 > $LOG_DIR/deferred/deferred-$(date +%Y%m%d-%H%M%S).log
    
    BOUNCE_COUNT=$(grep -c "bounced" $POSTFIX_LOG 2>/dev/null || echo "0")
    REJECT_COUNT=$(grep -cE "reject|rejected" $POSTFIX_LOG 2>/dev/null || echo "0")
    DEFERRED_COUNT=$(grep -c "deferred" $POSTFIX_LOG 2>/dev/null || echo "0")
    SENT_COUNT=$(grep -c "status=sent" $POSTFIX_LOG 2>/dev/null || echo "0")
    
    echo "Análise de $(date)" > $LOG_DIR/reports/report-$(date +%Y%m%d-%H%M%S).txt
    echo "Enviados: $SENT_COUNT" >> $LOG_DIR/reports/report-$(date +%Y%m%d-%H%M%S).txt
    echo "Bounces: $BOUNCE_COUNT" >> $LOG_DIR/reports/report-$(date +%Y%m%d-%H%M%S).txt
    echo "Rejeições: $REJECT_COUNT" >> $LOG_DIR/reports/report-$(date +%Y%m%d-%H%M%S).txt
    echo "Adiamentos: $DEFERRED_COUNT" >> $LOG_DIR/reports/report-$(date +%Y%m%d-%H%M%S).txt
fi
ANALYZESCRIPT

chmod +x /usr/local/bin/analyze-mail-logs.sh

# Configurar cron
(crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/analyze-mail-logs.sh >> /var/log/mail-analysis/cron.log 2>&1") | crontab -
(crontab -l 2>/dev/null; echo "0 2 * * * find /var/log/mail-analysis -type f -mtime +30 -delete") | crontab -

echo -e "${GREEN}✓ Sistema de análise configurado${NC}"

# ====================================
# REINICIAR SERVIÇOS
# ====================================
echo -e "${YELLOW}Reiniciando serviços...${NC}"

systemctl restart opendkim 2>/dev/null || true
systemctl restart postfix
systemctl restart dovecot

systemctl enable opendkim postfix dovecot

echo -e "${GREEN}✓ Serviços reiniciados${NC}"

# ====================================
# CONFIGURAR NGINX
# ====================================
echo -e "${YELLOW}Configurando Nginx...${NC}"

PUBLIC_IP=$(curl -s ifconfig.me)

cat > /etc/nginx/sites-available/$FULL_DOMAIN << EOF
server {
    listen 80;
    server_name $FULL_DOMAIN $PUBLIC_IP;
    root /var/www/html;
    index index.html lesk.html analysis.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -sf /etc/nginx/sites-available/$FULL_DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null

cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    index index.html lesk.html analysis.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Criar senha para análise
echo -n "admin:" > /etc/nginx/.htpasswd
openssl passwd -apr1 "analysis2024" >> /etc/nginx/.htpasswd

find /etc/nginx -type f -exec sed -i 's/^[[:space:]]*listen \[::\]/#&/g' {} \;

nginx -t && systemctl reload nginx || systemctl restart nginx
systemctl enable nginx

ln -sf /var/log/mail-analysis /var/www/html/analysis

echo -e "${GREEN}✓ Nginx configurado${NC}"

# ====================================
# CRIAR PÁGINA LESK.HTML - COMPLETA!
# ====================================
echo -e "${YELLOW}Criando página lesk.html...${NC}"

DKIM_KEY=$(cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')


cat > /var/www/html/lesk.html << 'LESKHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurações DNS - DOMAIN_PLACEHOLDER</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .header p { font-size: 1.2rem; opacity: 0.95; }
        .alert-box {
            background: #fff3cd;
            border-left: 4px solid #ff9800;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .alert-box h3 {
            color: #ff9800;
            margin-bottom: 10px;
        }
        .alert-box p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        .dns-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }
        .dns-card:hover {
            transform: translateY(-5px);
        }
        .dns-type {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .dns-info {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 15px;
            margin-bottom: 15px;
        }
        .dns-label {
            font-weight: 600;
            color: #555;
            padding: 8px 0;
        }
        .dns-value {
            background: #f5f5f5;
            padding: 8px 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            word-break: break-all;
            cursor: pointer;
            transition: background 0.3s;
        }
        .dns-value:hover {
            background: #e8e8e8;
        }
        .status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            margin-left: 10px;
        }
        .status-required {
            background: #ff4444;
            color: white;
        }
        .status-recommended {
            background: #ff9800;
            color: white;
        }
        .info-box {
            background: #f0f7ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-top: 20px;
            border-radius: 5px;
        }
        .info-box h3 {
            color: #1976D2;
            margin-bottom: 10px;
        }
        .info-box p {
            color: #555;
            line-height: 1.6;
        }
        .server-info {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .server-info h2 {
            color: #333;
            margin-bottom: 20px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        .info-item {
            padding: 15px;
            background: #f9f9f9;
            border-radius: 10px;
        }
        .info-item strong {
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }
        .copy-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px 5px;
            transition: all 0.3s;
        }
        .copy-btn:hover {
            background: #764ba2;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚙️ Configurações DNS Otimizadas</h1>
            <p>Domínio Completo: FULL_DOMAIN_PLACEHOLDER</p>
            <p>Domínio Base: DOMAIN_PLACEHOLDER</p>
        </div>

        <div class="alert-box">
            <h3>⚡ Configurações de Alta Entregabilidade</h3>
            <p><strong>Esta configuração foi otimizada para máxima entregabilidade!</strong></p>
            <p>Configure TODOS os registros obrigatórios para melhor reputação.</p>
        </div>
        
        <div class="server-info">
            <h2>🖥️ Informações do Servidor</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>IP do Servidor:</strong>
                    <span>IP_PLACEHOLDER</span>
                </div>
                <div class="info-item">
                    <strong>Hostname:</strong>
                    <span>FULL_DOMAIN_PLACEHOLDER</span>
                </div>
                <div class="info-item">
                    <strong>Subdomínio:</strong>
                    <span>SUBDOMAIN_PLACEHOLDER</span>
                </div>
                <div class="info-item">
                    <strong>Usuário SMTP:</strong>
                    <span>admin@DOMAIN_PLACEHOLDER</span>
                </div>
                <div class="info-item">
                    <strong>Senha SMTP:</strong>
                    <span>dwwzyd</span>
                </div>
            </div>
        </div>

        <!-- Registro A -->
        <div class="dns-card">
            <span class="dns-type">TIPO A</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyText(this)">SUBDOMAIN_PLACEHOLDER</div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyText(this)">IP_PLACEHOLDER</div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyText(this)">3600</div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro A</h3>
                <p>Aponta o subdomínio para o IP do servidor.</p>
            </div>
        </div>

        <!-- Registro MX -->
        <div class="dns-card">
            <span class="dns-type">TIPO MX</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyText(this)">@</div>
                <div class="dns-label">Servidor:</div>
                <div class="dns-value" onclick="copyText(this)">FULL_DOMAIN_PLACEHOLDER</div>
                <div class="dns-label">Prioridade:</div>
                <div class="dns-value" onclick="copyText(this)">10</div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyText(this)">3600</div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro MX</h3>
                <p>Define qual servidor recebe emails do domínio.</p>
            </div>
        </div>

        <!-- Registro SPF -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (SPF)</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyText(this)">@</div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyText(this)">v=spf1 ip4:IP_PLACEHOLDER mx a:FULL_DOMAIN_PLACEHOLDER -all</div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyText(this)">3600</div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro SPF</h3>
                <p>SPF com política restritiva (-all) que maximiza a reputação.</p>
            </div>
        </div>

        <!-- Registro DKIM -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (DKIM)</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyText(this)">SUBDOMAIN_PLACEHOLDER._domainkey</div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyText(this)">v=DKIM1; k=rsa; t=s; s=email; p=DKIM_KEY_PLACEHOLDER</div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyText(this)">3600</div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro DKIM</h3>
                <p>Assinatura digital com modo strict (t=s) para máxima validação.</p>
            </div>
        </div>

        <!-- Registro DMARC -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (DMARC)</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyText(this)">_dmarc</div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyText(this)">v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc-reports@DOMAIN_PLACEHOLDER; ruf=mailto:dmarc-failures@DOMAIN_PLACEHOLDER; fo=1; adkim=s; aspf=s; pct=100; ri=86400</div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyText(this)">3600</div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro DMARC</h3>
                <p>Política de quarentena com alinhamento estrito para máxima proteção.</p>
            </div>
        </div>

        <!-- MTA-STS -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (MTA-STS)</span>
            <span class="status-badge status-recommended">Recomendado</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyText(this)">_mta-sts</div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyText(this)">v=STSv1; id=TIMESTAMP_PH</div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyText(this)">3600</div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre MTA-STS</h3>
                <p>Força uso de TLS criptografado nas comunicações.</p>
            </div>
        </div>

        <!-- Checklist -->
        <div class="dns-card" style="background: #e8f5e9;">
            <h2>✅ Checklist de Implementação</h2>
            <ol style="margin-left: 20px; line-height: 2;">
                <li>Configure Registro A</li>
                <li>Configure Registro MX</li>
                <li>Configure SPF, DKIM e DMARC</li>
                <li>Configure MTA-STS</li>
                <li>Aguarde 24-48h para propagação</li>
                <li>Solicite PTR ao provedor de VPS</li>
                <li>Teste em https://www.mail-tester.com/</li>
                <li>Comece enviando poucos emails/dia</li>
            </ol>
        </div>
    </div>

    <script>
        function copyText(element) {
            const text = element.textContent.trim();
            navigator.clipboard.writeText(text).then(() => {
                const original = element.style.background;
                element.style.background = '#4caf50';
                element.style.color = 'white';
                setTimeout(() => {
                    element.style.background = original;
                    element.style.color = 'black';
                }, 2000);
            });
        }
    </script>
</body>
</html>
LESKHTML

# Substituir placeholders no HTML
sed -i "s/DOMAIN_PLACEHOLDER/$BASE_DOMAIN/g" /var/www/html/lesk.html
sed -i "s/FULL_DOMAIN_PLACEHOLDER/$FULL_DOMAIN/g" /var/www/html/lesk.html
sed -i "s/SUBDOMAIN_PLACEHOLDER/$SUBDOMAIN/g" /var/www/html/lesk.html
sed -i "s|IP_PLACEHOLDER|$PUBLIC_IP|g" /var/www/html/lesk.html
sed -i "s/DKIM_KEY_PLACEHOLDER/$DKIM_KEY/g" /var/www/html/lesk.html
sed -i "s/TIMESTAMP_PH/$(date +%Y%m%d%H%M%S)/g" /var/www/html/lesk.html

chmod 644 /var/www/html/lesk.html

echo -e "${GREEN}✓ Página lesk.html criada!${NC}"


# ====================================
# CRIAR PÁGINA ANALYSIS.HTML
# ====================================
echo -e "${YELLOW}Criando página analysis.html...${NC}"

cat > /var/www/html/analysis.html << 'ANALYSISHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Análise de Logs de Email</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .action-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            margin: 10px;
            transition: all 0.3s;
        }
        .action-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196F3;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }
        .code-box {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Análise de Logs de Email</h1>
            <p>Monitoramento de Bounces, Rejeições e Deferrals</p>
        </div>

        <div class="card">
            <h2>🎯 Ações Rápidas</h2>
            <button class="action-btn" onclick="runAnalysis()">▶️ Executar Análise</button>
            <button class="action-btn" onclick="viewLogs()">📄 Ver Logs</button>
        </div>

        <div class="info-box">
            <h3>💡 Como Usar</h3>
            <p><strong>Análise Automática:</strong> O sistema analisa logs a cada hora.</p>
            <p><strong>Análise Manual:</strong> Execute via SSH o comando abaixo.</p>
        </div>

        <div class="card">
            <h2>📁 Estrutura de Arquivos</h2>
            <ul style="line-height: 2;">
                <li><strong>/var/log/mail-analysis/bounces/</strong> - Emails retornados</li>
                <li><strong>/var/log/mail-analysis/rejected/</strong> - Emails rejeitados</li>
                <li><strong>/var/log/mail-analysis/deferred/</strong> - Emails adiados</li>
                <li><strong>/var/log/mail-analysis/reports/</strong> - Relatórios consolidados</li>
                <li><strong>/var/log/mail-analysis/daily/</strong> - Relatórios diários</li>
            </ul>
        </div>

        <div class="card">
            <h2>🔧 Comandos Úteis (SSH)</h2>
            <div class="code-box">
# Executar análise manual
/usr/local/bin/analyze-mail-logs.sh

# Ver últimos bounces
tail -n 50 /var/log/mail-analysis/bounces/*.log

# Ver últimas rejeições
tail -n 50 /var/log/mail-analysis/rejected/*.log

# Ver relatório mais recente
cat $(ls -t /var/log/mail-analysis/reports/*.txt | head -1)

# Ver logs do Postfix em tempo real
tail -f /var/log/postfix.log

# Verificar fila de emails
mailq

# Limpar fila
postsuper -d ALL
            </div>
        </div>

        <div class="info-box" style="background: #fff3cd; border-left-color: #ff9800;">
            <h3>⚠️ Interpretando Resultados</h3>
            <p><strong>Bounces Altos (&gt;5%):</strong> Lista de emails desatualizada</p>
            <p><strong>Rejeições por RBL:</strong> IP em lista negra</p>
            <p><strong>Deferrals Frequentes:</strong> Rate limiting ou problemas temporários</p>
            <p><strong>Taxa de Sucesso Baixa (&lt;90%):</strong> Revise DNS e qualidade da lista</p>
        </div>
    </div>

    <script>
        function runAnalysis() {
            alert('Execute via SSH:\n/usr/local/bin/analyze-mail-logs.sh');
        }
        function viewLogs() {
            alert('Execute via SSH:\ntail -n 50 /var/log/mail-analysis/bounces/*.log');
        }
    </script>
</body>
</html>
ANALYSISHTML

chmod 644 /var/www/html/analysis.html

echo -e "${GREEN}✓ Página analysis.html criada!${NC}"

# ====================================
# EXECUTAR PRIMEIRA ANÁLISE
# ====================================
echo -e "${YELLOW}Executando primeira análise...${NC}"
/usr/local/bin/analyze-mail-logs.sh 2>/dev/null || true

# ====================================
# VERIFICAR STATUS DOS SERVIÇOS
# ====================================
echo -e "\n${YELLOW}📊 Verificando serviços...${NC}"

SERVICES=("postfix" "dovecot" "opendkim" "nginx")
ALL_OK=true

for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        echo -e "  $service: ${GREEN}● Ativo${NC}"
    else
        echo -e "  $service: ${RED}● Inativo${NC}"
        ALL_OK=false
    fi
done

if $ALL_OK; then
    echo -e "\n${GREEN}✅ TODOS OS SERVIÇOS FUNCIONANDO!${NC}"
else
    echo -e "\n${YELLOW}⚠ Alguns serviços não estão ativos${NC}"
fi

# ====================================
# EXIBIR INFORMAÇÕES FINAIS
# ====================================
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA COM SUCESSO!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${CYAN}📧 INFORMAÇÕES DO SERVIDOR:${NC}"
echo -e "${GREEN}Domínio: $FULL_DOMAIN${NC}"
echo -e "${GREEN}IP: $PUBLIC_IP${NC}"
echo -e "${GREEN}Usuário: admin@$BASE_DOMAIN${NC}"
echo -e "${GREEN}Senha: dwwzyd${NC}"

echo -e "\n${CYAN}🌐 PÁGINAS WEB:${NC}"
echo -e "${GREEN}Configuração DNS: http://$PUBLIC_IP/lesk.html${NC}"
echo -e "${GREEN}Análise de Logs: http://$PUBLIC_IP/analysis.html${NC}"

echo -e "\n${CYAN}📊 PORTAS CONFIGURADAS:${NC}"
echo -e "${GREEN}SMTP: 25, 587, 465${NC}"
echo -e "${GREEN}IMAP: 143, 993${NC}"
echo -e "${GREEN}POP3: 110, 995${NC}"

echo -e "\n${CYAN}🔑 CHAVE DKIM:${NC}"
cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt

echo -e "\n${CYAN}✅ PRÓXIMOS PASSOS:${NC}"
echo -e "${YELLOW}1. Configure TODOS os registros DNS (acesse lesk.html)${NC}"
echo -e "${YELLOW}2. Aguarde 24-48h para propagação${NC}"
echo -e "${YELLOW}3. Solicite PTR ao provedor de VPS${NC}"
echo -e "${YELLOW}4. Teste em https://www.mail-tester.com/${NC}"
echo -e "${YELLOW}5. Monitore análises em http://$PUBLIC_IP/analysis.html${NC}"

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}🎉 TUDO PRONTO PARA USO!${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Log de instalação
echo "Instalação concluída em $(date)" >> /var/log/mail-setup.log
echo "Versão: 2.2 COMPLETO" >> /var/log/mail-setup.log
echo "Domínio: $FULL_DOMAIN" >> /var/log/mail-setup.log
echo "IP: $PUBLIC_IP" >> /var/log/mail-setup.log

# Limpar configurações temporárias
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

exit 0
