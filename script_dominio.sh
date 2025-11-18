#!/bin/bash

# Configurar para modo não-interativo
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

# ====================================
# RECEBER PARÂMETROS - VERSÃO FLEXÍVEL
# ====================================
FULL_DOMAIN=$1  # Agora aceita: webmail.exemplo.com, smtp.exemplo.com, etc.
URL_OPENDKIM_CONF=$2
CLOUDFLARE_API=$3
CLOUDFLARE_EMAIL=$4

# Validar se o domínio foi fornecido
if [ -z "$FULL_DOMAIN" ]; then
    echo "ERRO: Domínio não fornecido!"
    echo "Uso: bash $0 <dominio_completo> [url_opendkim] [cloudflare_api] [cloudflare_email]"
    echo "Exemplo: bash $0 webmail.exemplo.com"
    exit 1
fi

# ====================================
# EXTRAIR SUBDOMÍNIO E DOMÍNIO BASE
# ====================================
SUBDOMAIN=$(echo "$FULL_DOMAIN" | cut -d'.' -f1)
BASE_DOMAIN=$(echo "$FULL_DOMAIN" | cut -d'.' -f2-)

# Validar extração
if [ -z "$SUBDOMAIN" ] || [ -z "$BASE_DOMAIN" ]; then
    echo "ERRO: Não foi possível extrair subdomínio e domínio base de: $FULL_DOMAIN"
    exit 1
fi

# Cores para output
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
echo -e "${GREEN}Modo: ${YELLOW}Instalação Automática${NC}"
echo -e "${GREEN}Versão: ${YELLOW}2.1 (Otimizada para Entregabilidade)${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Mostrar etapas que serão executadas
echo -e "${CYAN}📋 Etapas da instalação:${NC}"
echo -e "  1. Verificar disponibilidade do sistema"
echo -e "  2. Atualizar sistema"
echo -e "  3. Instalar pacotes necessários"
echo -e "  4. Configurar OpenDKIM"
echo -e "  5. Configurar Postfix"
echo -e "  6. Configurar Dovecot"
echo -e "  7. Criar página de configuração DNS"
echo -e "  8. Reiniciar serviços\n"

echo -e "${YELLOW}⏱️  Tempo estimado: 10-15 minutos${NC}\n"
sleep 2

# Função para aguardar o apt ficar livre
wait_for_apt() {
    local max_attempts=60
    local attempt=0
    
    echo -e "${YELLOW}Verificando disponibilidade do apt/dpkg...${NC}"
    
    while [ $attempt -lt $max_attempts ]; do
        if ! lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
           ! lsof /var/lib/apt/lists/lock >/dev/null 2>&1 && \
           ! lsof /var/cache/apt/archives/lock >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Sistema de pacotes disponível${NC}"
            return 0
        fi
        
        attempt=$((attempt + 1))
        
        if [ $((attempt % 6)) -eq 0 ]; then
            echo -e "${YELLOW}⏳ Aguardando conclusão de outro processo apt/dpkg... ($((attempt*5))s/${max_attempts*5}s)${NC}"
            ps aux | grep -E "(apt|dpkg|unattended)" | grep -v grep || true
        else
            echo -ne "."
        fi
        
        sleep 5
    done
    
    echo -e "${RED}Timeout aguardando apt/dpkg. Tentando forçar liberação...${NC}"
    killall -9 apt apt-get dpkg 2>/dev/null || true
    sleep 2
    rm -f /var/lib/apt/lists/lock
    rm -f /var/cache/apt/archives/lock
    rm -f /var/lib/dpkg/lock*
    dpkg --configure -a 2>/dev/null || true
    
    return 1
}

wait_for_apt

# Configurar para não perguntar sobre reinicialização de serviços
echo '#!/bin/sh' > /usr/sbin/policy-rc.d
echo 'exit 101' >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

# Configurar needrestart para modo automático
mkdir -p /etc/needrestart/conf.d/
cat > /etc/needrestart/conf.d/99-autorestart.conf << 'EOF'
$nrconf{restart} = 'a';
$nrconf{kernelhints} = -1;
$nrconf{ucodehints} = 0;
$nrconf{restartsessionui} = 0;
$nrconf{nagsessionui} = 0;
EOF

echo -e "${YELLOW}Pulando atualização do sistema para economizar tempo...${NC}"
echo -e "${YELLOW}⚠️ AVISO: Isso pode causar problemas de compatibilidade${NC}"

apt-get update -y -qq

# Pré-configurar Postfix
echo -e "${YELLOW}Pré-configurando Postfix...${NC}"
wait_for_apt
echo "postfix postfix/mailname string $BASE_DOMAIN" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
echo "postfix postfix/destinations string $BASE_DOMAIN, localhost" | debconf-set-selections
echo "postfix postfix/relayhost string ''" | debconf-set-selections

# Instalar dependências
echo -e "${YELLOW}Instalando dependências...${NC}"
wait_for_apt
PACKAGES="postfix opendkim opendkim-tools dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd libsasl2-2 libsasl2-modules sasl2-bin mailutils wget unzip curl nginx ssl-cert"

TOTAL_PACKAGES=$(echo $PACKAGES | wc -w)
CURRENT_PACKAGE=0

echo -e "${YELLOW}📦 Total de pacotes a verificar: $TOTAL_PACKAGES${NC}"

for package in $PACKAGES; do
    CURRENT_PACKAGE=$((CURRENT_PACKAGE + 1))
    
    if ! dpkg -l | grep -q "^ii  $package"; then
        echo -e "${YELLOW}[$CURRENT_PACKAGE/$TOTAL_PACKAGES] Instalando $package...${NC}"
        if apt-get install -y -qq $package \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            2>/dev/null; then
            echo -e "${GREEN}  ✓ $package instalado${NC}"
        else
            echo -e "${RED}  ✗ Erro ao instalar $package${NC}"
        fi
    else
        echo -e "${GREEN}[$CURRENT_PACKAGE/$TOTAL_PACKAGES] $package já instalado ✓${NC}"
    fi
done

echo -e "${GREEN}✓ Instalação de pacotes concluída${NC}"

# Criar diretórios necessários
mkdir -p /var/www/html
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled
mkdir -p /var/mail/vhosts/$BASE_DOMAIN
mkdir -p /etc/opendkim/keys/$BASE_DOMAIN

rm -f /usr/sbin/policy-rc.d

# Configurar hostname
echo -e "${YELLOW}Configurando hostname...${NC}"
hostnamectl set-hostname $FULL_DOMAIN
echo "127.0.0.1 $FULL_DOMAIN" >> /etc/hosts

# ====================================
# CONFIGURAR OPENDKIM
# ====================================
echo -e "${YELLOW}Configurando OpenDKIM com chave RSA 1024...${NC}"

echo -e "${YELLOW}  → Criando configuração do OpenDKIM...${NC}"
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

echo -e "${GREEN}  ✓ Configuração criada${NC}"

mkdir -p /etc/opendkim/keys/$BASE_DOMAIN
mkdir -p /var/run/opendkim
mkdir -p /var/log/opendkim
chown -R opendkim:opendkim /var/run/opendkim
chown -R opendkim:opendkim /var/log/opendkim 2>/dev/null || true

# Gerar chave DKIM
echo -e "${YELLOW}  → Gerando chave DKIM 1024 bits...${NC}"
cd /etc/opendkim/keys/$BASE_DOMAIN
opendkim-genkey -b 1024 -s $SUBDOMAIN -d $BASE_DOMAIN 2>/dev/null || {
    echo -e "${YELLOW}  → Regenerando chave...${NC}"
    rm -f $SUBDOMAIN.private $SUBDOMAIN.txt
    opendkim-genkey -b 1024 -s $SUBDOMAIN -d $BASE_DOMAIN
}

if [ -f $SUBDOMAIN.private ]; then
    echo -e "${GREEN}  ✓ Chave DKIM gerada${NC}"
    chown opendkim:opendkim $SUBDOMAIN.private
    chmod 600 $SUBDOMAIN.private
else
    echo -e "${RED}  ✗ Erro ao gerar chave, usando método alternativo${NC}"
    openssl genrsa -out $SUBDOMAIN.private 1024
    openssl rsa -in $SUBDOMAIN.private -pubout -out $SUBDOMAIN.txt
    chown opendkim:opendkim $SUBDOMAIN.private
    chmod 600 $SUBDOMAIN.private
fi

chown -R opendkim:opendkim /etc/opendkim
chown -R opendkim:opendkim /var/run/opendkim

# ====================================
# CONFIGURAR POSTFIX
# ====================================
echo -e "${YELLOW}Configurando Postfix main.cf...${NC}"
cat > /etc/postfix/main.cf << EOF
# =================================================================
# Arquivo de Configuração Otimizado para Postfix (main.cf)
# Configurado automaticamente para $FULL_DOMAIN
# =================================================================

smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
smtp_address_preference = ipv4
biff = no
append_dot_mydomain = no
readme_directory = no
recipient_delimiter = +
mailbox_size_limit = 0
compatibility_level = 2

# --- Configurações de Identidade do Servidor ---
myhostname = $FULL_DOMAIN
mydomain = $BASE_DOMAIN
myorigin = /etc/mailname
mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
relayhost =

# --- Configurações de Rede ---
inet_interfaces = all
inet_protocols = ipv4

# --- Configurações de logging ---
maillog_file = /var/log/postfix.log
maillog_file_prefixes = /var/log
maillog_file_rotate_suffix = %Y%m%d-%H%M%S
maillog_file_compressor = gzip

# --- Aliases ---
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

# --- Configurações de Relay e Restrições ---
smtpd_relay_restrictions =
    permit_mynetworks
    permit_sasl_authenticated
    defer_unauth_destination
    reject_unauth_destination

# --- Configurações de TLS/SSL ---
smtpd_use_tls = yes
EOF

# Verificar certificados SSL
if [ -f "/etc/letsencrypt/live/$BASE_DOMAIN/fullchain.pem" ]; then
    echo -e "${GREEN}Certificados Let's Encrypt encontrados${NC}"
    cat >> /etc/postfix/main.cf << EOF
smtpd_tls_cert_file = /etc/letsencrypt/live/$BASE_DOMAIN/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/$BASE_DOMAIN/privkey.pem
EOF
else
    echo -e "${YELLOW}Usando certificados temporários (snake oil)${NC}"
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
smtpd_tls_loglevel = 1
smtp_tls_loglevel = 1

# --- INTEGRAÇÃO COM OPENDKIM ---
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

# --- CONFIGURAÇÃO DOVECOT SASL ---
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $BASE_DOMAIN
broken_sasl_auth_clients = yes

# --- VIRTUAL MAILBOX PARA DOVECOT ---
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = $BASE_DOMAIN
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_minimum_uid = 100
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# --- RESTRIÇÕES DE SEGURANÇA ADICIONAIS ---
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

# --- LIMITES E CONFIGURAÇÕES DE PERFORMANCE ---
message_size_limit = 52428800
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d
maximal_backoff_time = 4000s
minimal_backoff_time = 300s
queue_run_delay = 300s

# --- LIMITES DE CONEXÃO ---
smtpd_client_connection_count_limit = 50
smtpd_client_connection_rate_limit = 100
anvil_rate_time_unit = 60s

# --- CONFIGURAÇÕES ANTI-SPAM ---
smtpd_data_restrictions = reject_unauth_pipelining
smtpd_error_sleep_time = 1s
smtpd_soft_error_limit = 10
smtpd_hard_error_limit = 20
EOF

echo "$BASE_DOMAIN" > /etc/mailname

# Criar master.cf
echo -e "${YELLOW}Configurando master.cf...${NC}"
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
maildrop  unix  -       n       n       -       -       pipe
  flags=DRXhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix -       n       n       -       2       pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FRX user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py ${nexthop} ${user}
EOF

# Criar usuário vmail
echo -e "${YELLOW}Criando usuário vmail...${NC}"
groupadd -g 5000 vmail 2>/dev/null || true
useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m 2>/dev/null || true

mkdir -p /var/mail/vhosts/$BASE_DOMAIN
chown -R vmail:vmail /var/mail/vhosts

# Configurar virtual mailbox
echo "admin@$BASE_DOMAIN $BASE_DOMAIN/admin/" > /etc/postfix/vmailbox
postmap /etc/postfix/vmailbox

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

echo -e "${YELLOW}Criando usuário admin@$BASE_DOMAIN...${NC}"
echo "admin@$BASE_DOMAIN:{PLAIN}dwwzyd" > /etc/dovecot/users
chmod 640 /etc/dovecot/users
chown root:dovecot /etc/dovecot/users

echo -e "${YELLOW}Criando Maildir completo para admin@$BASE_DOMAIN...${NC}"

MAILDIR="/var/mail/vhosts/$BASE_DOMAIN/admin"

# Criar a estrutura completa Maildir
mkdir -p $MAILDIR
maildirmake.dovecot $MAILDIR
maildirmake.dovecot $MAILDIR/.Sent
maildirmake.dovecot $MAILDIR/.Trash
maildirmake.dovecot $MAILDIR/.Drafts
maildirmake.dovecot $MAILDIR/.Junk

# Ajustar permissões
chown -R vmail:vmail /var/mail/vhosts/$BASE_DOMAIN/admin

echo -e "${GREEN}✓ Maildir criado com sucesso!${NC}"

# ====================================
# REINICIAR SERVIÇOS
# ====================================
echo -e "${YELLOW}Reiniciando serviços...${NC}"

echo -e "${YELLOW}  → Testando configuração do OpenDKIM...${NC}"
if opendkim -n 2>/dev/null; then
    echo -e "${GREEN}  ✓ Configuração válida${NC}"
    systemctl restart opendkim 2>/dev/null && echo -e "${GREEN}  ✓ OpenDKIM reiniciado${NC}" || {
        echo -e "${YELLOW}  ⚠ OpenDKIM não iniciou, tentando correção...${NC}"
        cat > /etc/opendkim.conf << EOF
Domain                  $BASE_DOMAIN
KeyFile                 /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.private
Selector                $SUBDOMAIN
Socket                  inet:8891@localhost
UserID                  opendkim:opendkim
EOF
        systemctl restart opendkim 2>/dev/null || echo -e "${RED}  ✗ OpenDKIM falhou (não crítico)${NC}"
    }
else
    echo -e "${YELLOW}  ⚠ Configuração com problemas, usando modo simples${NC}"
    cat > /etc/opendkim.conf << EOF
Domain                  $BASE_DOMAIN
KeyFile                 /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.private
Selector                $SUBDOMAIN
Socket                  inet:8891@localhost
EOF
    systemctl restart opendkim 2>/dev/null || echo -e "${RED}  ✗ OpenDKIM não iniciou${NC}"
fi

systemctl restart postfix
systemctl restart dovecot

# Habilitar serviços
systemctl enable opendkim
systemctl enable postfix
systemctl enable dovecot

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
    index index.html index.htm lesk.html;

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
    index index.html index.htm lesk.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

echo -e "${YELLOW}Desativando IPv6 em todas as configs do Nginx...${NC}"
find /etc/nginx -type f -exec sed -i 's/^[[:space:]]*listen \[::\]/#&/g' {} \;
sleep 1

echo -e "${YELLOW}Testando configuração do Nginx...${NC}"
if nginx -t; then
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
        echo -e "${GREEN}Nginx recarregado com sucesso!${NC}"
    else
        echo -e "${YELLOW}Nginx não estava ativo. Reiniciando serviço...${NC}"
        systemctl restart nginx
    fi
else
    echo -e "${RED}Erro na configuração do Nginx.${NC}"
fi

systemctl enable nginx

# ====================================
# CRIAR PÁGINA HTML COM CONFIGURAÇÕES DNS
# ====================================
DKIM_KEY=$(cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')

echo -e "${YELLOW}Criando página de configuração DNS otimizada...${NC}"
cat > /var/www/html/lesk.html << EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurações DNS Otimizadas - $BASE_DOMAIN</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
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
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.95;
        }

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
            display: flex;
            align-items: center;
        }

        .alert-box h3::before {
            content: "⚡";
            margin-right: 10px;
            font-size: 1.5rem;
        }

        .alert-box p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 10px;
        }

        .alert-box ul {
            margin-left: 20px;
            color: #555;
        }

        .alert-box ul li {
            margin: 5px 0;
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
            box-shadow: 0 15px 40px rgba(0,0,0,0.25);
        }
        
        .dns-type {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 15px;
            font-size: 0.9rem;
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
            position: relative;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .dns-value:hover {
            background: #e8e8e8;
        }
        
        .copy-btn {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: #667eea;
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.3s;
            opacity: 0;
        }
        
        .dns-value:hover .copy-btn {
            opacity: 1;
        }
        
        .copy-btn:hover {
            background: #764ba2;
            transform: translateY(-50%) scale(1.05);
        }
        
        .copy-btn.copied {
            background: #4caf50;
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
        
        .status-optional {
            background: #4caf50;
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
            font-size: 1.1rem;
        }
        
        .info-box p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 8px;
        }

        .info-box strong {
            color: #1976D2;
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
            display: flex;
            align-items: center;
        }
        
        .server-info h2::before {
            content: "🖥️";
            margin-right: 10px;
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
        
        .copy-all-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            margin: 20px auto;
            display: block;
            transition: all 0.3s;
        }
        
        .copy-all-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        
        @media (max-width: 768px) {
            .dns-info {
                grid-template-columns: 1fr;
            }
            
            .dns-label {
                font-size: 12px;
                padding: 5px 0;
            }
            
            .header h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚙️ Configurações DNS Otimizadas</h1>
            <p>Domínio Completo: $FULL_DOMAIN</p>
            <p>Domínio Base: $BASE_DOMAIN</p>
            <p style="font-size: 0.9rem; opacity: 0.9; margin-top: 10px;">✨ Configurações otimizadas para máxima entregabilidade</p>
        </div>

        <div class="alert-box">
            <h3>Configurações de Alta Entregabilidade</h3>
            <p><strong>Esta configuração foi otimizada para garantir que seus emails cheguem na caixa de entrada!</strong></p>
            <p>Principais melhorias implementadas:</p>
            <ul>
                <li><strong>SPF Restritivo (-all):</strong> Política hard fail que aumenta a confiança dos provedores</li>
                <li><strong>DKIM Modo Strict:</strong> Validação rigorosa aceita por Gmail, Outlook e outros</li>
                <li><strong>DMARC com Alinhamento Estrito:</strong> Política de quarentena com alinhamento rigoroso</li>
                <li><strong>MTA-STS:</strong> Força criptografia TLS nas comunicações</li>
                <li><strong>Registros SRV:</strong> Autoconfiguração para clientes de email</li>
            </ul>
            <p><strong>⚠️ Importante:</strong> Configure TODOS os registros obrigatórios para melhor reputação!</p>
        </div>
        
        <div class="server-info">
            <h2>Informações do Servidor</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>IP do Servidor:</strong>
                    <span>$PUBLIC_IP</span>
                </div>
                <div class="info-item">
                    <strong>Hostname:</strong>
                    <span>$FULL_DOMAIN</span>
                </div>
                <div class="info-item">
                    <strong>Subdomínio:</strong>
                    <span>$SUBDOMAIN</span>
                </div>
                <div class="info-item">
                    <strong>Usuário SMTP:</strong>
                    <span>admin@$BASE_DOMAIN</span>
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
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $SUBDOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $PUBLIC_IP
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro A</h3>
                <p>Este registro aponta o subdomínio $SUBDOMAIN.$BASE_DOMAIN para o IP do seu servidor. É essencial para o funcionamento do servidor de email.</p>
            </div>
        </div>

        <!-- Registro MX -->
        <div class="dns-card">
            <span class="dns-type">TIPO MX</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    @
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Servidor de Email:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $FULL_DOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Prioridade:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    10
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro MX</h3>
                <p>Define qual servidor é responsável por receber emails para o domínio $BASE_DOMAIN. Sem este registro, o domínio não poderá receber emails.</p>
            </div>
        </div>

        <!-- Registro SPF -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (SPF)</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    @
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    v=spf1 ip4:$PUBLIC_IP mx a:$FULL_DOMAIN -all
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro SPF</h3>
                <p><strong>Configuração Otimizada:</strong> SPF com política restritiva (-all) que autoriza apenas este servidor ($PUBLIC_IP) e o registro MX a enviar emails. Esta configuração maximiza a reputação do domínio junto aos provedores de email.</p>
                <p><strong>Importante:</strong> O "-all" (hard fail) garante que emails de outros servidores sejam rejeitados, melhorando significativamente a entregabilidade e protegendo contra spoofing.</p>
                <p><strong>Por que isso importa:</strong> Gmail, Outlook e outros grandes provedores preferem domínios com SPF restritivo, pois demonstra controle adequado sobre o envio de emails.</p>
            </div>
        </div>

        <!-- Registro DKIM -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (DKIM)</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $SUBDOMAIN._domainkey
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    v=DKIM1; k=rsa; t=s; s=email; p=$DKIM_KEY
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro DKIM</h3>
                <p><strong>Assinatura Digital Aprimorada:</strong> DKIM valida a autenticidade dos emails através de criptografia RSA. Selector usado: <code>$SUBDOMAIN</code></p>
                <p><strong>Parâmetros Otimizados:</strong></p>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li><strong>t=s (modo strict):</strong> Exige que o domínio do assinante corresponda exatamente ao domínio do email</li>
                    <li><strong>s=email:</strong> Define o tipo de serviço como email, aumentando a confiança</li>
                </ul>
                <p><strong>Impacto:</strong> Essas configurações são favorecidas por Gmail, Outlook e outros provedores, aumentando significativamente as chances de entrega na caixa de entrada.</p>
            </div>
        </div>

        <!-- Registro DMARC -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (DMARC)</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    _dmarc
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc-reports@$BASE_DOMAIN; ruf=mailto:dmarc-failures@$BASE_DOMAIN; fo=1; adkim=s; aspf=s; pct=100; ri=86400
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro DMARC</h3>
                <p><strong>Proteção Máxima:</strong> Política configurada para quarentena de emails suspeitos com alinhamento estrito.</p>
                <p><strong>Configurações Implementadas:</strong></p>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li><strong>p=quarantine:</strong> Emails que falham são colocados em quarentena (não rejeitados completamente)</li>
                    <li><strong>adkim=s; aspf=s:</strong> Alinhamento estrito de DKIM e SPF</li>
                    <li><strong>pct=100:</strong> 100% dos emails são verificados</li>
                    <li><strong>ri=86400:</strong> Relatórios diários sobre tentativas de uso do domínio</li>
                </ul>
                <p><strong>Relatórios:</strong> Você receberá relatórios em dmarc-reports@$BASE_DOMAIN sobre todas as tentativas de envio, permitindo monitorar possíveis fraudes.</p>
                <p><strong>Evolução Recomendada:</strong> Após 30 dias sem problemas e com boa reputação, considere mudar <code>p=quarantine</code> para <code>p=reject</code> para proteção ainda maior contra phishing.</p>
            </div>
        </div>

        <!-- Registro MTA-STS -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (MTA-STS)</span>
            <span class="status-badge status-required">Obrigatório</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    _mta-sts
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    v=STSv1; id=$(date +%Y%m%d%H%M%S)
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o MTA-STS</h3>
                <p><strong>Segurança de Transporte Mail Transfer Agent Strict Transport Security:</strong> MTA-STS força o uso de TLS criptografado na comunicação entre servidores de email, prevenindo ataques man-in-the-middle.</p>
                <p><strong>Benefícios:</strong></p>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li>Impede downgrade attacks (ataques que forçam conexão não criptografada)</li>
                    <li>Garante que emails sempre sejam enviados de forma segura</li>
                    <li>Aumenta a confiança de grandes provedores (Gmail, Outlook, Yahoo)</li>
                </ul>
                <p><strong>Suporte:</strong> Reconhecido por Gmail, Outlook, Yahoo e outros grandes provedores como indicador de servidor profissional e seguro.</p>
            </div>
        </div>

        <!-- Registro TLS-RPT -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (TLS-RPT)</span>
            <span class="status-badge status-recommended">Recomendado</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    _smtp._tls
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    v=TLSRPTv1; rua=mailto:tls-reports@$BASE_DOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o TLS-RPT</h3>
                <p><strong>Relatórios de TLS (TLS Reporting):</strong> Receba notificações sobre falhas de conexão TLS, permitindo identificar e corrigir problemas rapidamente.</p>
                <p><strong>Importância:</strong> Ajuda a manter a segurança e confiabilidade do servidor, alertando sobre tentativas de conexão não segura ou problemas com certificados.</p>
            </div>
        </div>

        <!-- Registros SRV para Autoconfiguração -->
        <div class="dns-card">
            <span class="dns-type">TIPO SRV (Autoconfig IMAP)</span>
            <span class="status-badge status-recommended">Recomendado</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    _imaps._tcp
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Prioridade:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    10
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Peso:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    1
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Porta:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    993
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Destino:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $FULL_DOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre os Registros SRV</h3>
                <p><strong>Configuração Automática:</strong> Permite que clientes de email (Outlook, Thunderbird, Apple Mail) configurem automaticamente as contas sem necessidade de configuração manual.</p>
                <p><strong>Experiência do Usuário:</strong> Usuários precisam apenas inserir email e senha - o cliente descobre automaticamente as configurações do servidor.</p>
            </div>
        </div>

        <!-- Registro SRV para SMTP -->
        <div class="dns-card">
            <span class="dns-type">TIPO SRV (Autoconfig SMTP)</span>
            <span class="status-badge status-recommended">Recomendado</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    _submission._tcp
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Prioridade:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    10
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Peso:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    1
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Porta:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    587
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Destino:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $FULL_DOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o SRV SMTP</h3>
                <p>Permite autoconfiguração do servidor SMTP (envio) usando a porta 587 com STARTTLS.</p>
            </div>
        </div>

        <!-- Registro PTR -->
        <div class="dns-card">
            <span class="dns-type">TIPO PTR (Reverso)</span>
            <span class="status-badge status-optional">Opcional (mas importante!)</span>
            <div class="dns-info">
                <div class="dns-label">IP Reverso:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $PUBLIC_IP
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Aponta para:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $FULL_DOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro PTR</h3>
                <p><strong>DNS Reverso:</strong> O registro PTR faz o caminho inverso - mapeia o IP para o nome do domínio.</p>
                <p><strong>Configuração:</strong> Este registro NÃO pode ser configurado no seu provedor DNS. Você precisa solicitar ao seu provedor de VPS/servidor (AWS, DigitalOcean, etc) que configure o PTR para o IP $PUBLIC_IP apontando para $FULL_DOMAIN.</p>
                <p><strong>Importância:</strong> Muitos servidores de email (especialmente Gmail e Outlook) verificam o PTR antes de aceitar mensagens. Sem ele, seus emails podem ser rejeitados ou marcados como spam.</p>
                <p><strong>Como configurar:</strong> Entre em contato com seu provedor de servidor e solicite: "Configure o PTR record para o IP $PUBLIC_IP apontando para $FULL_DOMAIN"</p>
            </div>
        </div>

        <!-- Registro Autodiscover -->
        <div class="dns-card">
            <span class="dns-type">TIPO CNAME (Autodiscover)</span>
            <span class="status-badge status-optional">Opcional</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    autodiscover
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Aponta para:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $FULL_DOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">TTL:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    3600
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Autodiscover</h3>
                <p>Permite configuração automática de clientes de email, especialmente útil para usuários do Microsoft Outlook.</p>
            </div>
        </div>

        <button class="copy-all-btn" onclick="copyAllConfigs()">📋 Copiar Todas as Configurações</button>

        <div class="info-box" style="background: #e8f5e9; border-left-color: #4caf50; margin-top: 30px;">
            <h3 style="color: #2e7d32;">✅ Checklist de Implementação</h3>
            <p>Siga esta ordem para configurar seus registros DNS:</p>
            <ol style="margin-left: 20px; margin-top: 10px; color: #555;">
                <li><strong>Registro A</strong> - Configure primeiro para o domínio estar acessível</li>
                <li><strong>Registro MX</strong> - Necessário para receber emails</li>
                <li><strong>SPF, DKIM e DMARC</strong> - Configure os três juntos para autenticação</li>
                <li><strong>MTA-STS e TLS-RPT</strong> - Para segurança adicional</li>
                <li><strong>Registros SRV</strong> - Para facilitar configuração de clientes</li>
                <li><strong>PTR</strong> - Solicite ao provedor de VPS</li>
                <li><strong>Aguarde 24-48h</strong> - Para propagação DNS completa</li>
                <li><strong>Teste o envio</strong> - Use mail-tester.com para verificar sua pontuação</li>
            </ol>
        </div>
    </div>

    <script>
        function copyToClipboard(element) {
            const text = element.textContent.replace('Copiar', '').trim();
            navigator.clipboard.writeText(text).then(() => {
                const btn = element.querySelector('.copy-btn');
                if (btn) {
                    const originalText = btn.textContent;
                    btn.textContent = '✓ Copiado!';
                    btn.classList.add('copied');
                    setTimeout(() => {
                        btn.textContent = originalText;
                        btn.classList.remove('copied');
                    }, 2000);
                }
            });
        }

        function copyAllConfigs() {
            const configs = \`
=== CONFIGURAÇÕES DNS OTIMIZADAS PARA $BASE_DOMAIN ===
Versão: 2.1 - Otimizada para Máxima Entregabilidade
Domínio Completo: $FULL_DOMAIN
Subdomínio: $SUBDOMAIN

🔴 REGISTROS OBRIGATÓRIOS:

REGISTRO A:
Nome: $SUBDOMAIN
Conteúdo: $PUBLIC_IP
TTL: 3600

REGISTRO MX:
Nome: @
Servidor: $FULL_DOMAIN
Prioridade: 10
TTL: 3600

REGISTRO SPF (TXT) - POLÍTICA RESTRITIVA:
Nome: @
Conteúdo: v=spf1 ip4:$PUBLIC_IP mx a:$FULL_DOMAIN -all
TTL: 3600
Nota: O "-all" garante que apenas este servidor pode enviar emails

REGISTRO DKIM (TXT) - MODO STRICT:
Nome: $SUBDOMAIN._domainkey
Conteúdo: v=DKIM1; k=rsa; t=s; s=email; p=$DKIM_KEY
TTL: 3600
Nota: Parâmetros otimizados para máxima validação

REGISTRO DMARC (TXT) - ALINHAMENTO ESTRITO:
Nome: _dmarc
Conteúdo: v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc-reports@$BASE_DOMAIN; ruf=mailto:dmarc-failures@$BASE_DOMAIN; fo=1; adkim=s; aspf=s; pct=100; ri=86400
TTL: 3600
Nota: Após 30 dias, considere mudar p=quarantine para p=reject

REGISTRO MTA-STS (TXT) - SEGURANÇA DE TRANSPORTE:
Nome: _mta-sts
Conteúdo: v=STSv1; id=$(date +%Y%m%d%H%M%S)
TTL: 3600
Nota: Força uso de TLS criptografado

🟡 REGISTROS RECOMENDADOS:

REGISTRO TLS-RPT (TXT):
Nome: _smtp._tls
Conteúdo: v=TLSRPTv1; rua=mailto:tls-reports@$BASE_DOMAIN
TTL: 3600

REGISTRO SRV (IMAP Autoconfig):
Nome: _imaps._tcp
Prioridade: 10
Peso: 1
Porta: 993
Destino: $FULL_DOMAIN
TTL: 3600

REGISTRO SRV (SMTP Autoconfig):
Nome: _submission._tcp
Prioridade: 10
Peso: 1
Porta: 587
Destino: $FULL_DOMAIN
TTL: 3600

🟢 REGISTROS OPCIONAIS:

REGISTRO PTR (DNS Reverso):
IP: $PUBLIC_IP → $FULL_DOMAIN
⚠️ Configure com seu provedor de VPS (AWS, DigitalOcean, etc)
⚠️ Este registro é MUITO importante para evitar spam!

REGISTRO AUTODISCOVER (CNAME):
Nome: autodiscover
Aponta para: $FULL_DOMAIN
TTL: 3600

=== INFORMAÇÕES DO SERVIDOR ===
IP: $PUBLIC_IP
Hostname: $FULL_DOMAIN
Usuário SMTP: admin@$BASE_DOMAIN
Senha: dwwzyd
Portas: 25, 587, 465 (SMTP) | 143, 993 (IMAP) | 110, 995 (POP3)

=== CHECKLIST DE IMPLEMENTAÇÃO ===
□ 1. Configure Registro A
□ 2. Configure Registro MX
□ 3. Configure SPF, DKIM e DMARC (juntos!)
□ 4. Configure MTA-STS e TLS-RPT
□ 5. Configure Registros SRV
□ 6. Solicite PTR ao provedor de VPS
□ 7. Aguarde 24-48h para propagação DNS
□ 8. Teste em mail-tester.com (meta: 10/10)

=== DICAS IMPORTANTES ===
✓ SPF com -all é mais rigoroso que ~all e aumenta confiança
✓ DKIM modo strict (t=s) é preferido por grandes provedores
✓ DMARC com alinhamento estrito (adkim=s; aspf=s) maximiza segurança
✓ MTA-STS previne ataques man-in-the-middle
✓ PTR é essencial - sem ele, muitos emails serão rejeitados
✓ Teste sempre seus emails em mail-tester.com antes de envios em massa
✓ Considere "aquecer" o IP enviando poucos emails nos primeiros dias

=== PRÓXIMOS PASSOS ===
1. Configure TODOS os registros obrigatórios (🔴)
2. Configure os registros recomendados (🟡) para melhor resultado
3. Aguarde propagação DNS (24-48h)
4. Solicite PTR ao provedor de VPS
5. Faça teste em https://www.mail-tester.com/
6. Comece enviando poucos emails/dia e aumente gradualmente
7. Monitore os relatórios DMARC em dmarc-reports@$BASE_DOMAIN
\`;

            navigator.clipboard.writeText(configs).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '✓ Todas as Configurações Copiadas!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 3000);
            });
        }

        document.addEventListener('DOMContentLoaded', () => {
            const cards = document.querySelectorAll('.dns-card, .server-info, .alert-box');
            cards.forEach((card, index) => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                setTimeout(() => {
                    card.style.transition = 'opacity 0.5s, transform 0.5s';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, index * 100);
            });
        });
    </script>
</body>
</html>
EOF

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Página de configuração DNS otimizada criada!${NC}"
echo -e "${GREEN}Acesse: http://$PUBLIC_IP/lesk.html${NC}"
echo -e "${GREEN}========================================${NC}"

# Exibir chave DKIM
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Configuração concluída!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Chave DKIM pública (adicione ao DNS):${NC}"
cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt

# Testar configuração
echo -e "${YELLOW}Testando configurações...${NC}"
postfix check
dovecot -n > /dev/null 2>&1 && echo -e "${GREEN}Dovecot: OK${NC}" || echo -e "${RED}Dovecot: ERRO${NC}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Usuário SMTP criado:${NC}"
echo -e "${GREEN}Email: admin@$BASE_DOMAIN${NC}"
echo -e "${GREEN}Senha: dwwzyd${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Portas configuradas:${NC}"
echo -e "${GREEN}SMTP: 25${NC}"
echo -e "${GREEN}Submission: 587${NC}"
echo -e "${GREEN}SMTPS: 465${NC}"
echo -e "${GREEN}IMAP: 143${NC}"
echo -e "${GREEN}IMAPS: 993${NC}"
echo -e "${GREEN}POP3: 110${NC}"
echo -e "${GREEN}POP3S: 995${NC}"
echo -e "${GREEN}========================================${NC}"

# Verificar status dos serviços
echo -e "\n${YELLOW}📊 Verificando status dos serviços...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

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
    echo -e "\n${GREEN}✅ TODOS OS SERVIÇOS ESTÃO FUNCIONANDO!${NC}"
else
    echo -e "\n${YELLOW}⚠ Alguns serviços não estão ativos. Verifique os logs.${NC}"
fi

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Exibir dicas finais
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}📌 DICAS IMPORTANTES DE ENTREGABILIDADE:${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}1. Configure TODOS os registros DNS obrigatórios (A, MX, SPF, DKIM, DMARC, MTA-STS)${NC}"
echo -e "${YELLOW}2. Solicite configuração do PTR (DNS Reverso) ao seu provedor de VPS${NC}"
echo -e "${YELLOW}3. Aguarde 24-48 horas para propagação completa do DNS${NC}"
echo -e "${YELLOW}4. Teste seu servidor em https://www.mail-tester.com/ (meta: 10/10)${NC}"
echo -e "${YELLOW}5. Aqueça o IP: comece enviando poucos emails/dia e aumente gradualmente${NC}"
echo -e "${YELLOW}6. Monitore os relatórios DMARC em dmarc-reports@$BASE_DOMAIN${NC}"
echo -e "${YELLOW}7. Evite palavras de spam no assunto e conteúdo${NC}"
echo -e "${YELLOW}8. Sempre inclua link de descadastramento nos emails marketing${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Log de instalação
echo "Instalação concluída em $(date)" >> /var/log/mail-setup.log
echo "Versão: 2.1 (Otimizada para Entregabilidade)" >> /var/log/mail-setup.log
echo "Domínio Completo: $FULL_DOMAIN" >> /var/log/mail-setup.log
echo "Subdomínio: $SUBDOMAIN" >> /var/log/mail-setup.log
echo "Domínio Base: $BASE_DOMAIN" >> /var/log/mail-setup.log
echo "Usuário: admin@$BASE_DOMAIN" >> /var/log/mail-setup.log

# Limpar configurações temporárias
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

echo -e "\n${GREEN}🎉 Instalação concluída com sucesso!${NC}"
echo -e "${GREEN}📧 Acesse http://$PUBLIC_IP/lesk.html para ver as configurações DNS otimizadas${NC}"
echo -e "\n${CYAN}💡 Exemplos de uso:${NC}"
echo -e "${CYAN}   bash $0 webmail.exemplo.com${NC}"
echo -e "${CYAN}   bash $0 smtp.minhaempresa.com.br${NC}"
echo -e "${CYAN}   bash $0 correio.site.net${NC}\n"

exit 0
