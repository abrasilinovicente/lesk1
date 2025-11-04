#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# INSTALADOR SMTP - MULTI-USUÁRIO v3.3 FINAL
# ════════════════════════════════════════════════════════════════════════════
# - Autenticação SASL funcionando
# - Porta 587 com STARTTLS
# - Correção IPv6 do Dovecot
# - DKIM 1024 bits
# ════════════════════════════════════════════════════════════════════════════

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
    echo "Exemplo: bash $0 mail.seudominio.com"
    exit 1
fi

# ====================================
# EXTRAIR SUBDOMÍNIO E DOMÍNIO BASE
# ====================================
SUBDOMAIN=$(echo "$FULL_DOMAIN" | cut -d'.' -f1)
BASE_DOMAIN=$(echo "$FULL_DOMAIN" | cut -d'.' -f2-)

if [ -z "$SUBDOMAIN" ] || [ -z "$BASE_DOMAIN" ]; then
    echo "ERRO: Não foi possível extrair subdomínio e domínio base de: $FULL_DOMAIN"
    exit 1
fi

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   INSTALADOR SMTP - MULTI-USUÁRIO v3.3   ║${NC}"
echo -e "${GREEN}║   AUTENTICAÇÃO SASL + CORREÇÃO IPv6       ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Domínio: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}║ Subdomínio: ${YELLOW}$SUBDOMAIN${NC}"
echo -e "${GREEN}║ Base: ${YELLOW}$BASE_DOMAIN${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

sleep 2

# ====================================
# DETECTAR IP PÚBLICO
# ====================================
echo -e "${YELLOW}Detectando IP público...${NC}"

PUBLIC_IP=""
IP_SERVICES=(
    "ifconfig.me"
    "icanhazip.com"
    "ipecho.net/plain"
    "checkip.amazonaws.com"
    "api.ipify.org"
    "ipinfo.io/ip"
)

for service in "${IP_SERVICES[@]}"; do
    IP=$(curl -s --connect-timeout 5 "$service" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    if [ ! -z "$IP" ]; then
        PUBLIC_IP="$IP"
        echo -e "${GREEN}✓ IP detectado: $PUBLIC_IP (via $service)${NC}"
        break
    fi
done

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(hostname -I | awk '{print $1}')
    echo -e "${YELLOW}⚠ IP detectado via hostname: $PUBLIC_IP${NC}"
fi

if [[ ! $PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}✗ ERRO: Não foi possível detectar um IP válido!${NC}"
    echo -e "${YELLOW}Por favor, insira o IP público manualmente:${NC}"
    read -p "IP: " PUBLIC_IP
    
    if [[ ! $PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${RED}IP inválido! Abortando...${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ IP confirmado: $PUBLIC_IP${NC}\n"
sleep 2

# ====================================
# FUNÇÃO WAIT_FOR_APT
# ====================================
wait_for_apt() {
    local max_attempts=60
    local attempt=0
    
    echo -e "${YELLOW}Verificando apt/dpkg...${NC}"
    
    while [ $attempt -lt $max_attempts ]; do
        if ! lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
           ! lsof /var/lib/apt/lists/lock >/dev/null 2>&1 && \
           ! lsof /var/cache/apt/archives/lock >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Sistema disponível${NC}"
            return 0
        fi
        
        attempt=$((attempt + 1))
        [ $((attempt % 6)) -eq 0 ] && echo -e "${YELLOW}⏳ Aguardando... ($((attempt*5))s)${NC}" || echo -ne "."
        sleep 5
    done
    
    echo -e "${RED}Timeout! Forçando liberação...${NC}"
    killall -9 apt apt-get dpkg 2>/dev/null || true
    rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
    dpkg --configure -a 2>/dev/null || true
    return 1
}

wait_for_apt

# ====================================
# CONFIGURAÇÕES NÃO-INTERATIVAS
# ====================================
echo '#!/bin/sh' > /usr/sbin/policy-rc.d
echo 'exit 101' >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

mkdir -p /etc/needrestart/conf.d/
cat > /etc/needrestart/conf.d/99-autorestart.conf << 'EOF'
$nrconf{restart} = 'a';
$nrconf{kernelhints} = -1;
EOF

apt-get update -y -qq

# ====================================
# PRÉ-CONFIGURAR POSTFIX
# ====================================
echo -e "${YELLOW}Pré-configurando Postfix...${NC}"
wait_for_apt
echo "postfix postfix/mailname string $BASE_DOMAIN" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# ====================================
# INSTALAR PACOTES
# ====================================
echo -e "${YELLOW}Instalando pacotes...${NC}"
wait_for_apt
PACKAGES="postfix opendkim opendkim-tools dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd libsasl2-2 libsasl2-modules sasl2-bin mailutils nginx ssl-cert"

for package in $PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $package"; then
        apt-get install -y -qq $package -o Dpkg::Options::="--force-confdef" 2>/dev/null && \
            echo -e "${GREEN}✓ $package${NC}" || echo -e "${RED}✗ $package${NC}"
    fi
done

# ====================================
# CRIAR DIRETÓRIOS
# ====================================
mkdir -p /var/www/html /etc/nginx/sites-{available,enabled} /var/mail/vhosts/$BASE_DOMAIN /etc/opendkim/keys/$BASE_DOMAIN
rm -f /usr/sbin/policy-rc.d

# ====================================
# HOSTNAME
# ====================================
hostnamectl set-hostname $FULL_DOMAIN
echo "127.0.0.1 $FULL_DOMAIN" >> /etc/hosts

# ====================================
# OPENDKIM - 1024 BITS
# ====================================
echo -e "${YELLOW}Gerando chave DKIM 1024 bits...${NC}"
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

mkdir -p /var/run/opendkim /var/log/opendkim
chown -R opendkim:opendkim /var/run/opendkim /var/log/opendkim 2>/dev/null || true

cd /etc/opendkim/keys/$BASE_DOMAIN
rm -f $SUBDOMAIN.private $SUBDOMAIN.txt
opendkim-genkey -b 1024 -s $SUBDOMAIN -d $BASE_DOMAIN 2>/dev/null || opendkim-genkey -b 1024 -s $SUBDOMAIN -d $BASE_DOMAIN

if [ -f $SUBDOMAIN.private ]; then
    echo -e "${GREEN}✓ Chave DKIM 1024 bits gerada!${NC}"
    chown opendkim:opendkim $SUBDOMAIN.private
    chmod 600 $SUBDOMAIN.private
else
    echo -e "${RED}✗ Erro! Usando método alternativo...${NC}"
    openssl genrsa -out $SUBDOMAIN.private 1024
    chown opendkim:opendkim $SUBDOMAIN.private
    chmod 600 $SUBDOMAIN.private
fi

chown -R opendkim:opendkim /etc/opendkim

# ====================================
# POSTFIX - CONFIGURAÇÃO COMPLETA
# ====================================
echo -e "${YELLOW}Configurando Postfix com SASL...${NC}"
cat > /etc/postfix/main.cf << EOF
# ════════════════════════════════════════
# IDENTIFICAÇÃO
# ════════════════════════════════════════
smtpd_banner = \$myhostname ESMTP
smtp_address_preference = ipv4
biff = no
compatibility_level = 2

# ════════════════════════════════════════
# DOMÍNIOS
# ════════════════════════════════════════
myhostname = $FULL_DOMAIN
mydomain = $BASE_DOMAIN
myorigin = /etc/mailname
mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain
mynetworks = 127.0.0.0/8
relayhost =

inet_interfaces = all
inet_protocols = ipv4

alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

# ════════════════════════════════════════
# RELAY E RESTRIÇÕES - CRÍTICO
# ════════════════════════════════════════
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination

# ════════════════════════════════════════
# TLS/SSL - MELHORADO
# ════════════════════════════════════════
smtpd_use_tls = yes
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level = may
smtpd_tls_auth_only = no
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s

# Cliente SMTP TLS
smtp_tls_security_level = may
smtp_tls_loglevel = 1

# ════════════════════════════════════════
# DKIM
# ════════════════════════════════════════
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

# ════════════════════════════════════════
# SASL - AUTENTICAÇÃO CRÍTICA
# ════════════════════════════════════════
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
broken_sasl_auth_clients = yes

# ════════════════════════════════════════
# VIRTUAL DOMAINS
# ════════════════════════════════════════
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = $BASE_DOMAIN
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# ════════════════════════════════════════
# LIMITES
# ════════════════════════════════════════
message_size_limit = 52428800
mailbox_size_limit = 0

# ════════════════════════════════════════
# SEGURANÇA ADICIONAL
# ════════════════════════════════════════
smtpd_helo_required = yes
smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname

smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated

smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated

smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_invalid_recipient_domain, reject_non_fqdn_recipient
EOF

echo "$BASE_DOMAIN" > /etc/mailname

# ====================================
# POSTFIX MASTER.CF - PORTA 587
# ====================================
echo -e "${YELLOW}Configurando master.cf com porta 587...${NC}"
cat > /etc/postfix/master.cf << 'EOFMASTER'
# ════════════════════════════════════════════════════════════════════════════
# service type  private unpriv  chroot  wakeup  maxproc command + args
# ════════════════════════════════════════════════════════════════════════════

# Porta 25 - SMTP padrão
smtp      inet  n       -       y       -       -       smtpd

# Porta 587 - SUBMISSION (REQUER AUTENTICAÇÃO) - CRÍTICO
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_sasl_security_options=noanonymous
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# Serviços internos
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
EOFMASTER

# ====================================
# DOVECOT - COM CORREÇÃO IPv6
# ====================================
echo -e "${YELLOW}Configurando Dovecot (IPv4 apenas)...${NC}"
groupadd -g 5000 vmail 2>/dev/null || true
useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m 2>/dev/null || true

cat > /etc/dovecot/dovecot.conf << EOFDOVE
# ════════════════════════════════════════
# CORREÇÃO IPv6 - CRÍTICO
# ════════════════════════════════════════
listen = *

# ════════════════════════════════════════
# PROTOCOLOS
# ════════════════════════════════════════
protocols = imap pop3 lmtp

# ════════════════════════════════════════
# MAIL LOCATION
# ════════════════════════════════════════
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail
first_valid_uid = 5000
last_valid_uid = 5000

# ════════════════════════════════════════
# SSL/TLS
# ════════════════════════════════════════
ssl = yes
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_min_protocol = TLSv1.2

# ════════════════════════════════════════
# AUTENTICAÇÃO - CRÍTICO
# ════════════════════════════════════════
auth_mechanisms = plain login
disable_plaintext_auth = no
auth_username_format = %Ln

# ════════════════════════════════════════
# LMTP SERVICE - ENTREGA DE EMAIL
# ════════════════════════════════════════
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
  user = vmail
}

# ════════════════════════════════════════
# AUTH SERVICE - CRÍTICO PARA SMTP
# ════════════════════════════════════════
service auth {
  # Socket para Postfix SMTP AUTH
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  
  # Socket para autenticação IMAP/POP3
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }
  
  user = dovecot
}

# ════════════════════════════════════════
# PASSDB E USERDB
# ════════════════════════════════════════
passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/users
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n allow_all_users=yes
}

# ════════════════════════════════════════
# LOGGING - PARA DEBUG
# ════════════════════════════════════════
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log
debug_log_path = /var/log/dovecot-debug.log
auth_verbose = yes
auth_debug = yes
mail_debug = yes

# ════════════════════════════════════════
# NAMESPACE
# ════════════════════════════════════════
namespace inbox {
  inbox = yes
  
  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
  
  mailbox Spam {
    special_use = \Junk
    auto = subscribe
  }
}
EOFDOVE

# Criar arquivos de log
touch /var/log/dovecot.log /var/log/dovecot-info.log /var/log/dovecot-debug.log
chown dovecot:dovecot /var/log/dovecot*.log

# ====================================
# CRIAR MÚLTIPLOS USUÁRIOS
# ====================================
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}     CRIANDO USUÁRIOS DE EMAIL${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}\n"

# Lista de usuários (usuario:senha)
# EDITE AQUI PARA ADICIONAR/REMOVER USUÁRIOS
USUARIOS=(
    "admin:dwwzyd"
    "vendas:senha123"
    "suporte:suporte2024"
    "contato:contato@123"
    "info:info456"
    "comercial:comercial789"
    "financeiro:financeiro@2024"
    "marketing:marketing321"
    "rh:rh@2024"
    "ti:ti@secure"
    "compras:compras@2024"
)

# Limpar arquivos
> /etc/dovecot/users
> /etc/postfix/vmailbox

echo -e "${YELLOW}Total de usuários a criar: ${#USUARIOS[@]}${NC}\n"

CONTADOR=0

for usuario in "${USUARIOS[@]}"; do
    USERNAME=$(echo "$usuario" | cut -d':' -f1)
    SENHA=$(echo "$usuario" | cut -d':' -f2)
    
    if [ -z "$USERNAME" ] || [ -z "$SENHA" ]; then
        echo -e "${RED}✗ Usuário inválido: $usuario${NC}"
        continue
    fi
    
    EMAIL="$USERNAME@$BASE_DOMAIN"
    
    # Adicionar ao Dovecot
    echo "$EMAIL:{PLAIN}$SENHA" >> /etc/dovecot/users
    
    # Criar diretório
    mkdir -p /var/mail/vhosts/$BASE_DOMAIN/$USERNAME/{cur,new,tmp}
    chown -R vmail:vmail /var/mail/vhosts/$BASE_DOMAIN/$USERNAME
    chmod -R 700 /var/mail/vhosts/$BASE_DOMAIN/$USERNAME
    
    # Adicionar ao Postfix
    echo "$EMAIL $BASE_DOMAIN/$USERNAME/" >> /etc/postfix/vmailbox
    
    echo -e "${GREEN}✓ $EMAIL (senha: $SENHA)${NC}"
    CONTADOR=$((CONTADOR + 1))
done

# Permissões
chmod 640 /etc/dovecot/users
chown root:dovecot /etc/dovecot/users
chown -R vmail:vmail /var/mail/vhosts/$BASE_DOMAIN

# Atualizar mapa do Postfix
postmap /etc/postfix/vmailbox

echo -e "\n${GREEN}✅ Total de usuários criados: $CONTADOR${NC}\n"

# ====================================
# REINICIAR SERVIÇOS NA ORDEM CORRETA
# ====================================
echo -e "${YELLOW}Iniciando serviços...${NC}"

# Parar todos primeiro
systemctl stop opendkim postfix dovecot 2>/dev/null

# Limpar sockets antigos
rm -f /var/spool/postfix/private/auth 2>/dev/null
rm -f /var/spool/postfix/private/dovecot-lmtp 2>/dev/null

# Iniciar na ordem correta
echo -e "${YELLOW}Iniciando OpenDKIM...${NC}"
systemctl start opendkim
sleep 2

echo -e "${YELLOW}Iniciando Dovecot...${NC}"
systemctl start dovecot
sleep 3

echo -e "${YELLOW}Iniciando Postfix...${NC}"
systemctl start postfix
sleep 2

# Habilitar no boot
systemctl enable opendkim postfix dovecot 2>/dev/null

# ====================================
# VERIFICAR STATUS DOS SERVIÇOS
# ====================================
echo -e "\n${YELLOW}Verificando status dos serviços...${NC}"
SERVICOS_OK=0

for service in opendkim dovecot postfix; do
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}✓ $service está rodando${NC}"
        SERVICOS_OK=$((SERVICOS_OK + 1))
    else
        echo -e "${RED}✗ $service NÃO está rodando${NC}"
        echo -e "${YELLOW}Tentando mais uma vez...${NC}"
        systemctl restart $service
        sleep 2
        if systemctl is-active --quiet $service; then
            echo -e "${GREEN}✓ $service iniciado!${NC}"
            SERVICOS_OK=$((SERVICOS_OK + 1))
        else
            echo -e "${RED}✗ $service falhou!${NC}"
            systemctl status $service --no-pager -l
        fi
    fi
done

# Verificar socket de autenticação
echo -e "\n${YELLOW}Verificando socket de autenticação...${NC}"
TENTATIVAS=0
while [ $TENTATIVAS -lt 5 ]; do
    if [ -S /var/spool/postfix/private/auth ]; then
        echo -e "${GREEN}✓ Socket de autenticação criado!${NC}"
        ls -la /var/spool/postfix/private/auth
        break
    else
        echo -e "${YELLOW}Aguardando socket... (tentativa $((TENTATIVAS+1))/5)${NC}"
        sleep 2
        TENTATIVAS=$((TENTATIVAS + 1))
    fi
done

if [ ! -S /var/spool/postfix/private/auth ]; then
    echo -e "${RED}✗ AVISO: Socket não foi criado!${NC}"
    echo -e "${YELLOW}Isso pode causar problemas de autenticação.${NC}"
fi

# ====================================
# NGINX
# ====================================
echo -e "\n${YELLOW}Configurando Nginx...${NC}"

cat > /etc/nginx/sites-available/$FULL_DOMAIN << EOFNGINX
server {
    listen 80;
    server_name $FULL_DOMAIN $PUBLIC_IP;
    root /var/www/html;
    index index.html;
    location / { try_files \$uri \$uri/ =404; }
}
EOFNGINX

ln -sf /etc/nginx/sites-available/$FULL_DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

if nginx -t 2>/dev/null; then
    systemctl restart nginx 2>/dev/null
    systemctl enable nginx 2>/dev/null
    echo -e "${GREEN}✓ Nginx configurado${NC}"
fi

# ====================================
# PÁGINA HTML COM CONFIGURAÇÕES
# ====================================
DKIM_KEY=$(cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')

echo -e "\n${YELLOW}Criando página de configurações DNS...${NC}"

# Gerar lista de usuários para HTML
USERS_HTML=""
for usuario in "${USUARIOS[@]}"; do
    USERNAME=$(echo "$usuario" | cut -d':' -f1)
    SENHA=$(echo "$usuario" | cut -d':' -f2)
    EMAIL="$USERNAME@$BASE_DOMAIN"
    USERS_HTML="$USERS_HTML
                <div class='info-item'>
                    <strong>$EMAIL</strong>
                    <span>Senha: $SENHA</span>
                </div>"
done

cat > /var/www/html/index.html << 'EOFHTML'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuração SMTP - DOMAIN_PLACEHOLDER</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            text-align: center;
        }
        .header h1 { color: #667eea; font-size: 2rem; margin-bottom: 10px; }
        .ip-display {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 10px;
            font-size: 1.3rem;
            font-weight: bold;
            margin: 15px 0;
            display: inline-block;
        }
        .dns-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .dns-type {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 15px;
            font-size: 1.1rem;
        }
        .dns-field {
            margin: 12px 0;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .dns-field strong {
            color: #667eea;
            display: block;
            margin-bottom: 8px;
            font-size: 0.95rem;
        }
        .dns-value {
            background: #ffffff;
            border: 2px solid #667eea;
            padding: 12px 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            word-break: break-all;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
        }
        .dns-value:hover {
            background: #f0f0f0;
            border-color: #764ba2;
        }
        .dns-value::after {
            content: '📋 Clique para copiar';
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 11px;
            color: #999;
            font-family: 'Segoe UI', sans-serif;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .info-item {
            padding: 15px;
            background: #f9f9f9;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .info-item strong {
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        .warning ul {
            margin-left: 20px;
            margin-top: 10px;
        }
        .warning li {
            margin: 8px 0;
        }
        .success-msg {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            color: #155724;
        }
        .auth-config {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        .auth-config h3 {
            color: #1976D2;
            margin-bottom: 15px;
        }
        .copy-notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 15px 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            display: none;
            z-index: 1000;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        .port-info {
            background: #fff9e6;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div id="copyNotification" class="copy-notification">✓ Copiado!</div>
    
    <div class="container">
        <div class="header">
            <h1>⚙️ Configuração SMTP Concluída</h1>
            <p style="margin: 10px 0;"><strong>Domínio:</strong> FULL_DOMAIN_PLACEHOLDER</p>
            <div class="ip-display">🌐 IP do Servidor: PUBLIC_IP_PLACEHOLDER</div>
            <p style="margin-top: 10px;"><strong>Total de usuários criados:</strong> CONTADOR_PLACEHOLDER</p>
            <p style="margin-top: 5px; color: #666;"><small>🔐 DKIM: 1024 bits | Autenticação SASL: ✓ | IPv6: Desabilitado</small></p>
        </div>

        <div class="success-msg">
            <strong>✅ Instalação concluída com autenticação SASL e correção IPv6!</strong>
            <p style="margin-top: 8px;">Todos os serviços configurados. Configure os DNS e teste.</p>
        </div>

        <!-- CONFIGURAÇÃO DE AUTENTICAÇÃO -->
        <div class="auth-config">
            <h3>🔐 CONFIGURAÇÃO DE AUTENTICAÇÃO SMTP</h3>
            <p><strong>IMPORTANTE:</strong> Use estas configurações no seu cliente de email:</p>
            <ul style="margin-top: 15px; margin-left: 20px;">
                <li><strong>Servidor SMTP:</strong> <code>FULL_DOMAIN_PLACEHOLDER</code></li>
                <li><strong>Porta:</strong> <code>587</code> (submission - RECOMENDADO) ou <code>25</code></li>
                <li><strong>Tipo de segurança:</strong> STARTTLS (porta 587) ou Nenhum (porta 25)</li>
                <li><strong>Requer autenticação:</strong> SIM ✓</li>
                <li><strong>Nome de usuário:</strong> Email completo (ex: admin@BASE_DOMAIN_PLACEHOLDER)</li>
                <li><strong>Senha:</strong> A senha do usuário</li>
            </ul>
            <div class="port-info">
                <strong>⚡ Porta 587 vs Porta 25:</strong>
                <ul style="margin-left: 20px; margin-top: 8px;">
                    <li><strong>Porta 587:</strong> Submission port, usa STARTTLS, mais segura ✓</li>
                    <li><strong>Porta 25:</strong> Porta padrão SMTP, sem criptografia obrigatória</li>
                </ul>
            </div>
        </div>

        <div class="warning">
            <strong>⚠️ IMPORTANTE - CONFIGURAÇÃO DNS:</strong>
            <ul>
                <li><strong>Use <code>~all</code> no SPF</strong> (NÃO use <code>-all</code>)</li>
                <li><strong>IP detectado:</strong> <code>PUBLIC_IP_PLACEHOLDER</code> - Verifique se está correto!</li>
                <li>Configure TODOS os registros DNS abaixo</li>
                <li>Aguarde 1-6 horas para propagação DNS</li>
                <li>Teste autenticação SMTP na porta 587</li>
            </ul>
        </div>

        <!-- USUÁRIOS -->
        <div class="dns-card">
            <span class="dns-type">👥 USUÁRIOS DE EMAIL (CONTADOR_PLACEHOLDER)</span>
            <div class="info-grid">USERS_HTML_PLACEHOLDER
            </div>
        </div>

        <!-- SERVIDOR -->
        <div class="dns-card">
            <span class="dns-type">📧 CONFIGURAÇÕES DO SERVIDOR</span>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Servidor SMTP (Envio)</strong>
                    <span>FULL_DOMAIN_PLACEHOLDER</span>
                </div>
                <div class="info-item">
                    <strong>Porta SMTP</strong>
                    <span>587 (STARTTLS) ou 25</span>
                </div>
                <div class="info-item">
                    <strong>Autenticação SMTP</strong>
                    <span>✓ Obrigatória</span>
                </div>
                <div class="info-item">
                    <strong>Servidor IMAP</strong>
                    <span>FULL_DOMAIN_PLACEHOLDER</span>
                </div>
                <div class="info-item">
                    <strong>Porta IMAP</strong>
                    <span>143</span>
                </div>
            </div>
        </div>

        <!-- REGISTRO A -->
        <div class="dns-card">
            <span class="dns-type">🔵 Registro A</span>
            <div class="dns-field">
                <strong>Tipo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'A')">A</div>
            </div>
            <div class="dns-field">
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'SUBDOMAIN_PLACEHOLDER')">SUBDOMAIN_PLACEHOLDER</div>
            </div>
            <div class="dns-field">
                <strong>IP:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'PUBLIC_IP_PLACEHOLDER')">PUBLIC_IP_PLACEHOLDER</div>
            </div>
        </div>

        <!-- REGISTRO MX -->
        <div class="dns-card">
            <span class="dns-type">📨 Registro MX</span>
            <div class="dns-field">
                <strong>Tipo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'MX')">MX</div>
            </div>
            <div class="dns-field">
                <strong>Nome:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '@')">@</div>
            </div>
            <div class="dns-field">
                <strong>Servidor:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'FULL_DOMAIN_PLACEHOLDER')">FULL_DOMAIN_PLACEHOLDER</div>
            </div>
            <div class="dns-field">
                <strong>Prioridade:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '10')">10</div>
            </div>
        </div>

        <!-- SPF -->
        <div class="dns-card">
            <span class="dns-type">🔒 SPF</span>
            <div class="dns-field">
                <strong>Tipo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'TXT')">TXT</div>
            </div>
            <div class="dns-field">
                <strong>Nome:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '@')">@</div>
            </div>
            <div class="dns-field">
                <strong>Valor:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'SPF_VALUE_PLACEHOLDER')">SPF_VALUE_PLACEHOLDER</div>
            </div>
        </div>

        <!-- DKIM -->
        <div class="dns-card">
            <span class="dns-type">🔐 DKIM</span>
            <div class="dns-field">
                <strong>Tipo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'TXT')">TXT</div>
            </div>
            <div class="dns-field">
                <strong>Nome:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'DKIM_NAME_PLACEHOLDER')">DKIM_NAME_PLACEHOLDER</div>
            </div>
            <div class="dns-field">
                <strong>Valor:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'DKIM_VALUE_PLACEHOLDER')">DKIM_VALUE_PLACEHOLDER</div>
            </div>
        </div>

        <!-- DMARC -->
        <div class="dns-card">
            <span class="dns-type">📋 DMARC</span>
            <div class="dns-field">
                <strong>Tipo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'TXT')">TXT</div>
            </div>
            <div class="dns-field">
                <strong>Nome:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '_dmarc')">_dmarc</div>
            </div>
            <div class="dns-field">
                <strong>Valor:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'DMARC_VALUE_PLACEHOLDER')">DMARC_VALUE_PLACEHOLDER</div>
            </div>
        </div>

    </div>

    <script>
        function copyToClipboard(element, text) {
            const textToCopy = text || element.textContent.trim();
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                const original = element.style.background;
                const originalBorder = element.style.borderColor;
                element.style.background = '#28a745';
                element.style.borderColor = '#28a745';
                element.style.color = 'white';
                
                const notification = document.getElementById('copyNotification');
                notification.style.display = 'block';
                
                setTimeout(() => {
                    element.style.background = original;
                    element.style.borderColor = originalBorder;
                    element.style.color = '';
                    notification.style.display = 'none';
                }, 1500);
            });
        }
    </script>
</body>
</html>
EOFHTML

# Substituir placeholders
sed -i "s|DOMAIN_PLACEHOLDER|$BASE_DOMAIN|g" /var/www/html/index.html
sed -i "s|FULL_DOMAIN_PLACEHOLDER|$FULL_DOMAIN|g" /var/www/html/index.html
sed -i "s|BASE_DOMAIN_PLACEHOLDER|$BASE_DOMAIN|g" /var/www/html/index.html
sed -i "s|PUBLIC_IP_PLACEHOLDER|$PUBLIC_IP|g" /var/www/html/index.html
sed -i "s|SUBDOMAIN_PLACEHOLDER|$SUBDOMAIN|g" /var/www/html/index.html
sed -i "s|CONTADOR_PLACEHOLDER|$CONTADOR|g" /var/www/html/index.html
sed -i "s|USERS_HTML_PLACEHOLDER|$USERS_HTML|g" /var/www/html/index.html
sed -i "s|SPF_VALUE_PLACEHOLDER|v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all|g" /var/www/html/index.html
sed -i "s|DKIM_NAME_PLACEHOLDER|$SUBDOMAIN._domainkey|g" /var/www/html/index.html
sed -i "s|DKIM_VALUE_PLACEHOLDER|v=DKIM1; k=rsa; p=$DKIM_KEY|g" /var/www/html/index.html
sed -i "s|DMARC_VALUE_PLACEHOLDER|v=DMARC1; p=quarantine; rua=mailto:admin@$BASE_DOMAIN; aspf=r; adkim=r|g" /var/www/html/index.html

# ====================================
# RESUMO FINAL
# ====================================
echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       INSTALAÇÃO CONCLUÍDA!                ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Domínio: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}║ IP: ${YELLOW}$PUBLIC_IP${NC}"
echo -e "${GREEN}║ Usuários: ${YELLOW}$CONTADOR${NC}"
echo -e "${GREEN}║ Serviços OK: ${YELLOW}$SERVICOS_OK/3${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ 🌐 Acesse: ${CYAN}http://$PUBLIC_IP${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}📧 CONFIGURAÇÃO DO CLIENTE:${NC}"
echo -e "  ${GREEN}Servidor:${NC} $FULL_DOMAIN"
echo -e "  ${GREEN}Porta:${NC} 587 (STARTTLS recomendado)"
echo -e "  ${GREEN}Autenticação:${NC} Obrigatória"
echo -e "  ${GREEN}Usuário:${NC} email@$BASE_DOMAIN"
echo -e "  ${GREEN}Senha:${NC} a senha do usuário\n"

echo -e "${YELLOW}⚙️ COMANDOS ÚTEIS:${NC}"
echo -e "  Ver logs: ${CYAN}tail -f /var/log/mail.log${NC}"
echo -e "  Status: ${CYAN}systemctl status postfix dovecot${NC}"
echo -e "  Testar: ${CYAN}telnet $FULL_DOMAIN 587${NC}\n"

# Salvar resumo
cat > /root/smtp-config.txt << EOFSUMMARY
════════════════════════════════════════════════════════
        CONFIGURAÇÃO SMTP COMPLETA
════════════════════════════════════════════════════════

Data: $(date)
Domínio: $FULL_DOMAIN
IP: $PUBLIC_IP
Usuários: $CONTADOR

CONFIGURAÇÃO DO CLIENTE:
- Servidor SMTP: $FULL_DOMAIN
- Porta: 587 (STARTTLS) ou 25
- Autenticação: Obrigatória
- Usuário: email completo
- Senha: senha do usuário

USUÁRIOS:
EOFSUMMARY

for usuario in "${USUARIOS[@]}"; do
    USERNAME=$(echo "$usuario" | cut -d':' -f1)
    SENHA=$(echo "$usuario" | cut -d':' -f2)
    echo "$USERNAME@$BASE_DOMAIN : $SENHA" >> /root/smtp-config.txt
done

echo -e "\n${GREEN}✓ Resumo salvo: ${CYAN}/root/smtp-config.txt${NC}\n"

# Limpar
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         🎉 INSTALAÇÃO FINALIZADA!          ║${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}║  1. Configure os registros DNS             ║${NC}"
echo -e "${GREEN}║  2. Aguarde propagação (1-6h)              ║${NC}"
echo -e "${GREEN}║  3. Teste a autenticação                   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

exit 0
