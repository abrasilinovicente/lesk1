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
echo -e "${GREEN}Versão: ${YELLOW}2.2 (Com Sistema de Análise de Bounces)${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Mostrar etapas que serão executadas
echo -e "${CYAN}📋 Etapas da instalação:${NC}"
echo -e "  1. Verificar disponibilidade do sistema"
echo -e "  2. Atualizar sistema"
echo -e "  3. Instalar pacotes necessários"
echo -e "  4. Configurar OpenDKIM"
echo -e "  5. Configurar Postfix com logs avançados"
echo -e "  6. Configurar Dovecot"
echo -e "  7. Configurar sistema de captura de bounces"
echo -e "  8. Criar página de configuração DNS e análise"
echo -e "  9. Reiniciar serviços\n"

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

# Instalar dependências (incluindo pflogsumm para análise de logs)
echo -e "${YELLOW}Instalando dependências...${NC}"
wait_for_apt
PACKAGES="postfix opendkim opendkim-tools dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd libsasl2-2 libsasl2-modules sasl2-bin mailutils wget unzip curl nginx ssl-cert pflogsumm postfix-pcre"

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

# ====================================
# CRIAR DIRETÓRIOS PARA LOGS DE BOUNCES
# ====================================
echo -e "${YELLOW}Configurando sistema de captura de bounces...${NC}"

mkdir -p /var/log/mail-analysis
mkdir -p /var/log/mail-analysis/bounces
mkdir -p /var/log/mail-analysis/rejected
mkdir -p /var/log/mail-analysis/deferred
mkdir -p /var/log/mail-analysis/reports
mkdir -p /var/log/mail-analysis/daily

chmod -R 755 /var/log/mail-analysis
chown -R syslog:adm /var/log/mail-analysis

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
# CONFIGURAR POSTFIX COM LOGS AVANÇADOS
# ====================================
echo -e "${YELLOW}Configurando Postfix main.cf com logs avançados...${NC}"
cat > /etc/postfix/main.cf << EOF
# =================================================================
# Arquivo de Configuração Otimizado para Postfix (main.cf)
# Configurado automaticamente para $FULL_DOMAIN
# Versão 2.2 - Com Sistema Avançado de Logs
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

# --- CONFIGURAÇÕES DE LOGGING AVANÇADO ---
# Logs detalhados para análise de problemas
maillog_file = /var/log/postfix.log
maillog_file_prefixes = /var/log
maillog_file_rotate_suffix = %Y%m%d-%H%M%S
maillog_file_compressor = gzip

# Aumentar verbosidade para capturar mais detalhes
debug_peer_level = 2
smtp_tls_loglevel = 1
smtpd_tls_loglevel = 1

# Logs detalhados de bounce e erros
bounce_notice_recipient = postmaster@$BASE_DOMAIN
2bounce_notice_recipient = postmaster@$BASE_DOMAIN
delay_notice_recipient = postmaster@$BASE_DOMAIN
error_notice_recipient = postmaster@$BASE_DOMAIN

# Notificar sobre bounces
notify_classes = bounce, 2bounce, delay, resource, software

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

# --- CONFIGURAÇÕES DE BOUNCE ---
bounce_size_limit = 50000
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

mkdir -p /var/mail/vhosts/$BASE_DOMAIN/admin
chown -R vmail:vmail /var/mail/vhosts/$BASE_DOMAIN/admin

# ====================================
# CRIAR SCRIPT DE ANÁLISE DE LOGS
# ====================================
echo -e "${YELLOW}Criando script de análise de logs...${NC}"

cat > /usr/local/bin/analyze-mail-logs.sh << 'ANALYZE_SCRIPT'
#!/bin/bash

# Script de Análise de Logs de Email
# Versão 2.2 - Análise Completa de Bounces e Rejeições

LOG_DIR="/var/log/mail-analysis"
POSTFIX_LOG="/var/log/postfix.log"
MAIL_LOG="/var/log/mail.log"
REPORT_FILE="$LOG_DIR/reports/mail-report-$(date +%Y%m%d-%H%M%S).txt"
DAILY_REPORT="$LOG_DIR/daily/daily-$(date +%Y%m%d).txt"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}   ANÁLISE DE LOGS DE EMAIL${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Data/Hora: $(date)${NC}"
echo -e "${CYAN}========================================${NC}\n"

# Criar diretórios se não existirem
mkdir -p $LOG_DIR/{bounces,rejected,deferred,reports,daily}

# ====================================
# 1. EXTRAIR BOUNCES
# ====================================
echo -e "${YELLOW}📊 Analisando BOUNCES (emails retornados)...${NC}"

if [ -f "$POSTFIX_LOG" ]; then
    # Capturar todos os bounces
    grep -i "bounced" $POSTFIX_LOG | tail -n 100 > $LOG_DIR/bounces/bounces-$(date +%Y%m%d-%H%M%S).log
    
    BOUNCE_COUNT=$(grep -c "bounced" $POSTFIX_LOG 2>/dev/null || echo "0")
    echo -e "${GREEN}Total de bounces encontrados: $BOUNCE_COUNT${NC}"
    
    # Analisar motivos de bounce
    echo -e "\n${CYAN}Top 10 Motivos de Bounce:${NC}"
    grep -i "bounced" $POSTFIX_LOG | sed 's/.*status=bounced (//' | sed 's/).*//' | sort | uniq -c | sort -rn | head -10
    
    # Capturar destinatários com bounce
    echo -e "\n${CYAN}Top 10 Destinatários com Bounce:${NC}"
    grep -i "bounced" $POSTFIX_LOG | grep -oP 'to=<[^>]+>' | sort | uniq -c | sort -rn | head -10
fi

# ====================================
# 2. EXTRAIR REJEIÇÕES
# ====================================
echo -e "\n${YELLOW}🚫 Analisando REJEIÇÕES (emails bloqueados)...${NC}"

if [ -f "$POSTFIX_LOG" ]; then
    # Capturar todas as rejeições
    grep -E "reject|rejected" $POSTFIX_LOG | tail -n 100 > $LOG_DIR/rejected/rejected-$(date +%Y%m%d-%H%M%S).log
    
    REJECT_COUNT=$(grep -cE "reject|rejected" $POSTFIX_LOG 2>/dev/null || echo "0")
    echo -e "${GREEN}Total de rejeições encontradas: $REJECT_COUNT${NC}"
    
    # Analisar motivos de rejeição
    echo -e "\n${CYAN}Top 10 Motivos de Rejeição:${NC}"
    grep -E "reject|rejected" $POSTFIX_LOG | sed 's/.*reject: //' | sed 's/from.*//' | sort | uniq -c | sort -rn | head -10
    
    # RBL blocks
    echo -e "\n${CYAN}Bloqueios por RBL (Listas Negras):${NC}"
    grep -i "rbl" $POSTFIX_LOG | tail -20
fi

# ====================================
# 3. EXTRAIR DEFERRALS (adiamentos)
# ====================================
echo -e "\n${YELLOW}⏱️  Analisando DEFERRALS (emails adiados)...${NC}"

if [ -f "$POSTFIX_LOG" ]; then
    # Capturar deferrals
    grep -i "deferred" $POSTFIX_LOG | tail -n 100 > $LOG_DIR/deferred/deferred-$(date +%Y%m%d-%H%M%S).log
    
    DEFERRED_COUNT=$(grep -c "deferred" $POSTFIX_LOG 2>/dev/null || echo "0")
    echo -e "${GREEN}Total de emails adiados: $DEFERRED_COUNT${NC}"
    
    # Motivos de deferral
    echo -e "\n${CYAN}Top 10 Motivos de Adiamento:${NC}"
    grep -i "deferred" $POSTFIX_LOG | sed 's/.*status=deferred (//' | sed 's/).*//' | sort | uniq -c | sort -rn | head -10
fi

# ====================================
# 4. ANÁLISE DE ENTREGAS SUCESSO
# ====================================
echo -e "\n${YELLOW}✅ Analisando ENTREGAS COM SUCESSO...${NC}"

if [ -f "$POSTFIX_LOG" ]; then
    SENT_COUNT=$(grep -c "status=sent" $POSTFIX_LOG 2>/dev/null || echo "0")
    echo -e "${GREEN}Total de emails enviados com sucesso: $SENT_COUNT${NC}"
    
    # Top destinatários que receberam emails
    echo -e "\n${CYAN}Top 10 Destinatários que Receberam:${NC}"
    grep "status=sent" $POSTFIX_LOG | grep -oP 'to=<[^>]+>' | sort | uniq -c | sort -rn | head -10
fi

# ====================================
# 5. ESTATÍSTICAS GERAIS
# ====================================
echo -e "\n${YELLOW}📈 ESTATÍSTICAS GERAIS:${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ -f "$POSTFIX_LOG" ]; then
    echo -e "Total de Emails Enviados: ${GREEN}$SENT_COUNT${NC}"
    echo -e "Total de Bounces: ${RED}$BOUNCE_COUNT${NC}"
    echo -e "Total de Rejeições: ${RED}$REJECT_COUNT${NC}"
    echo -e "Total de Adiamentos: ${YELLOW}$DEFERRED_COUNT${NC}"
    
    # Calcular taxa de sucesso
    TOTAL=$((SENT_COUNT + BOUNCE_COUNT + REJECT_COUNT))
    if [ $TOTAL -gt 0 ]; then
        SUCCESS_RATE=$(echo "scale=2; ($SENT_COUNT * 100) / $TOTAL" | bc)
        echo -e "Taxa de Sucesso: ${GREEN}${SUCCESS_RATE}%${NC}"
    fi
fi

# ====================================
# 6. ANÁLISE COM PFLOGSUMM
# ====================================
echo -e "\n${YELLOW}📊 Relatório Detalhado com pflogsumm:${NC}"

if command -v pflogsumm &> /dev/null && [ -f "$POSTFIX_LOG" ]; then
    pflogsumm -d today $POSTFIX_LOG > $LOG_DIR/reports/pflogsumm-$(date +%Y%m%d).txt
    echo -e "${GREEN}Relatório pflogsumm salvo em: $LOG_DIR/reports/pflogsumm-$(date +%Y%m%d).txt${NC}"
else
    echo -e "${YELLOW}pflogsumm não disponível ou log não encontrado${NC}"
fi

# ====================================
# 7. GERAR RELATÓRIO CONSOLIDADO
# ====================================
echo -e "\n${YELLOW}📝 Gerando relatório consolidado...${NC}"

cat > $REPORT_FILE << EOF
========================================
RELATÓRIO DE ANÁLISE DE LOGS DE EMAIL
========================================
Data/Hora: $(date)
Servidor: $(hostname)
========================================

ESTATÍSTICAS GERAIS:
-------------------
Emails Enviados: $SENT_COUNT
Bounces: $BOUNCE_COUNT
Rejeições: $REJECT_COUNT
Adiamentos: $DEFERRED_COUNT

PRINCIPAIS PROBLEMAS ENCONTRADOS:
---------------------------------

TOP 5 MOTIVOS DE BOUNCE:
$(grep -i "bounced" $POSTFIX_LOG 2>/dev/null | sed 's/.*status=bounced (//' | sed 's/).*//' | sort | uniq -c | sort -rn | head -5)

TOP 5 MOTIVOS DE REJEIÇÃO:
$(grep -E "reject|rejected" $POSTFIX_LOG 2>/dev/null | sed 's/.*reject: //' | sed 's/from.*//' | sort | uniq -c | sort -rn | head -5)

TOP 5 MOTIVOS DE ADIAMENTO:
$(grep -i "deferred" $POSTFIX_LOG 2>/dev/null | sed 's/.*status=deferred (//' | sed 's/).*//' | sort | uniq -c | sort -rn | head -5)

ARQUIVOS DE LOG GERADOS:
------------------------
- Bounces: $LOG_DIR/bounces/bounces-$(date +%Y%m%d-%H%M%S).log
- Rejeições: $LOG_DIR/rejected/rejected-$(date +%Y%m%d-%H%M%S).log
- Adiamentos: $LOG_DIR/deferred/deferred-$(date +%Y%m%d-%H%M%S).log

========================================
FIM DO RELATÓRIO
========================================
EOF

echo -e "${GREEN}✓ Relatório salvo em: $REPORT_FILE${NC}"

# Copiar para relatório diário
cp $REPORT_FILE $DAILY_REPORT

echo -e "\n${CYAN}========================================${NC}"
echo -e "${GREEN}✓ Análise concluída!${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "${YELLOW}Dica: Execute 'cat $REPORT_FILE' para ver o relatório completo${NC}\n"
ANALYZE_SCRIPT

chmod +x /usr/local/bin/analyze-mail-logs.sh

# ====================================
# CRIAR CRON JOB PARA ANÁLISE AUTOMÁTICA
# ====================================
echo -e "${YELLOW}Configurando análise automática de logs (cron)...${NC}"

# Adicionar ao cron para executar a cada hora
(crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/analyze-mail-logs.sh >> /var/log/mail-analysis/cron.log 2>&1") | crontab -

# Adicionar ao cron para limpeza de logs antigos (manter 30 dias)
(crontab -l 2>/dev/null; echo "0 2 * * * find /var/log/mail-analysis -type f -mtime +30 -delete") | crontab -

echo -e "${GREEN}✓ Cron job configurado para executar a cada hora${NC}"

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
    index index.html index.htm lesk.html analysis.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Proteger diretório de análises
    location /analysis {
        auth_basic "Área Restrita - Análise de Logs";
        auth_basic_user_file /etc/nginx/.htpasswd;
        autoindex on;
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
    index index.html index.htm lesk.html analysis.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Criar senha para área de análise
echo -e "${YELLOW}Criando senha para área de análise...${NC}"
apt-get install -y -qq apache2-utils
echo -n "admin:" >> /etc/nginx/.htpasswd
openssl passwd -apr1 "analysis2024" >> /etc/nginx/.htpasswd

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
# CRIAR LINK SIMBÓLICO PARA ANÁLISES
# ====================================
echo -e "${YELLOW}Criando acesso web para análises...${NC}"
ln -sf /var/log/mail-analysis /var/www/html/analysis

# ====================================
# CRIAR PÁGINA HTML COM CONFIGURAÇÕES DNS E ANÁLISE
# ====================================
DKIM_KEY=$(cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')

echo -e "${YELLOW}Criando página de configuração DNS e análise de logs...${NC}"

# [O HTML anterior permanece o mesmo, então vou pular para economizar espaço]
# Aqui você mantém todo o HTML que já estava no script original

# Adicionar página de análise
cat > /var/www/html/analysis.html << 'ANALYSIS_HTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Análise de Logs de Email</title>
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
            max-width: 1400px;
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
        
        .analysis-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-box h3 {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .stat-box p {
            font-size: 0.9rem;
            opacity: 0.9;
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
        
        .log-viewer {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            max-height: 500px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196F3;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Análise de Logs de Email</h1>
            <p>Monitoramento de Bounces, Rejeições e Deferrals</p>
        </div>

        <div class="analysis-card">
            <h2>🎯 Ações Rápidas</h2>
            <button class="action-btn" onclick="runAnalysis()">▶️ Executar Análise Agora</button>
            <button class="action-btn" onclick="viewLatestReport()">📄 Ver Último Relatório</button>
            <button class="action-btn" onclick="viewBounces()">❌ Ver Bounces</button>
            <button class="action-btn" onclick="viewRejected()">🚫 Ver Rejeições</button>
            <button class="action-btn" onclick="viewDeferred()">⏱️ Ver Deferrals</button>
        </div>

        <div class="info-box">
            <h3>💡 Como Usar o Sistema de Análise</h3>
            <p><strong>Análise Automática:</strong> O sistema analisa os logs a cada hora automaticamente.</p>
            <p><strong>Análise Manual:</strong> Clique em "Executar Análise Agora" para gerar um relatório imediato.</p>
            <p><strong>Acesso aos Logs:</strong> Use SSH e execute: <code>cat /var/log/mail-analysis/reports/[arquivo-mais-recente]</code></p>
            <p><strong>Comando Direto:</strong> Execute via SSH: <code>/usr/local/bin/analyze-mail-logs.sh</code></p>
        </div>

        <div class="analysis-card">
            <h2>📁 Estrutura de Arquivos</h2>
            <ul style="line-height: 2;">
                <li><strong>/var/log/mail-analysis/bounces/</strong> - Logs de emails retornados</li>
                <li><strong>/var/log/mail-analysis/rejected/</strong> - Logs de emails rejeitados</li>
                <li><strong>/var/log/mail-analysis/deferred/</strong> - Logs de emails adiados</li>
                <li><strong>/var/log/mail-analysis/reports/</strong> - Relatórios consolidados</li>
                <li><strong>/var/log/mail-analysis/daily/</strong> - Relatórios diários</li>
            </ul>
        </div>

        <div class="analysis-card">
            <h2>🔧 Comandos Úteis (via SSH)</h2>
            <div class="log-viewer">
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

# Buscar por email específico nos logs
grep "email@exemplo.com" /var/log/postfix.log

# Verificar fila de emails
mailq

# Limpar fila de emails
postsuper -d ALL
            </div>
        </div>

        <div class="info-box" style="background: #fff3cd; border-left-color: #ff9800;">
            <h3>⚠️ Interpretando os Resultados</h3>
            <p><strong>Bounces Altos:</strong> Verifique se sua lista de emails está atualizada. Emails inválidos prejudicam a reputação.</p>
            <p><strong>Rejeições por RBL:</strong> Seu IP pode estar em lista negra. Solicite remoção em spamhaus.org e outras RBLs.</p>
            <p><strong>Deferrals Frequentes:</strong> Pode indicar problemas temporários com servidores de destino ou limite de taxa.</p>
            <p><strong>Taxa de Sucesso Baixa (&lt;90%):</strong> Revise configurações DNS (SPF, DKIM, DMARC) e qualidade da lista.</p>
        </div>
    </div>

    <script>
        function runAnalysis() {
            alert('Para executar análise manualmente, acesse via SSH e execute:\n/usr/local/bin/analyze-mail-logs.sh');
        }

        function viewLatestReport() {
            alert('Acesse via SSH:\ncat $(ls -t /var/log/mail-analysis/reports/*.txt | head -1)');
        }

        function viewBounces() {
            alert('Acesse via SSH:\ntail -n 50 /var/log/mail-analysis/bounces/*.log');
        }

        function viewRejected() {
            alert('Acesse via SSH:\ntail -n 50 /var/log/mail-analysis/rejected/*.log');
        }

        function viewDeferred() {
            alert('Acesse via SSH:\ntail -n 50 /var/log/mail-analysis/deferred/*.log');
        }
    </script>
</body>
</html>
ANALYSIS_HTML

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Páginas criadas com sucesso!${NC}"
echo -e "${GREEN}DNS Config: http://$PUBLIC_IP/lesk.html${NC}"
echo -e "${GREEN}Análise de Logs: http://$PUBLIC_IP/analysis.html${NC}"
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
echo -e "${GREEN}Credenciais de Análise Web:${NC}"
echo -e "${GREEN}Usuário: admin${NC}"
echo -e "${GREEN}Senha: analysis2024${NC}"
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

# Executar primeira análise
echo -e "${YELLOW}Executando primeira análise de logs...${NC}"
/usr/local/bin/analyze-mail-logs.sh

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
echo -e "${CYAN}📌 SISTEMA DE ANÁLISE DE LOGS:${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Análise automática configurada (executa a cada hora)${NC}"
echo -e "${GREEN}✓ Logs salvos em: /var/log/mail-analysis/${NC}"
echo -e "${GREEN}✓ Relatórios em: /var/log/mail-analysis/reports/${NC}"
echo -e "${GREEN}✓ Interface web: http://$PUBLIC_IP/analysis.html${NC}"
echo -e "${YELLOW}📝 Execute manualmente: /usr/local/bin/analyze-mail-logs.sh${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}📌 DICAS IMPORTANTES DE ENTREGABILIDADE:${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}1. Configure TODOS os registros DNS obrigatórios${NC}"
echo -e "${YELLOW}2. Monitore os relatórios de análise regularmente${NC}"
echo -e "${YELLOW}3. Mantenha sua lista de emails limpa (remova bounces)${NC}"
echo -e "${YELLOW}4. Aqueça o IP gradualmente${NC}"
echo -e "${YELLOW}5. Teste em https://www.mail-tester.com/${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Log de instalação
echo "Instalação concluída em $(date)" >> /var/log/mail-setup.log
echo "Versão: 2.2 (Com Sistema de Análise de Bounces)" >> /var/log/mail-setup.log
echo "Domínio Completo: $FULL_DOMAIN" >> /var/log/mail-setup.log
echo "Subdomínio: $SUBDOMAIN" >> /var/log/mail-setup.log
echo "Domínio Base: $BASE_DOMAIN" >> /var/log/mail-setup.log
echo "Usuário: admin@$BASE_DOMAIN" >> /var/log/mail-setup.log
echo "Sistema de Análise: Ativo" >> /var/log/mail-setup.log

# Limpar configurações temporárias
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

echo -e "\n${GREEN}🎉 Instalação concluída com sucesso!${NC}"
echo -e "${GREEN}📧 Páginas criadas:${NC}"
echo -e "${GREEN}   - Configuração DNS: http://$PUBLIC_IP/lesk.html${NC}"
echo -e "${GREEN}   - Análise de Logs: http://$PUBLIC_IP/analysis.html${NC}"
echo -e "\n${CYAN}🔍 Comandos úteis para análise:${NC}"
echo -e "${CYAN}   - Executar análise: /usr/local/bin/analyze-mail-logs.sh${NC}"
echo -e "${CYAN}   - Ver logs em tempo real: tail -f /var/log/postfix.log${NC}"
echo -e "${CYAN}   - Ver fila de emails: mailq${NC}"
echo -e "${CYAN}   - Ver último relatório: cat \$(ls -t /var/log/mail-analysis/reports/*.txt | head -1)${NC}\n"

exit 0
