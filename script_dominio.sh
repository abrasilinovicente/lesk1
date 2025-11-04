#!/bin/bash

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
    echo "Exemplo: bash $0 cool.nexoeabogados.com"
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
echo -e "${GREEN}║   INSTALADOR SMTP - MULTI-USUÁRIO v3.2   ║${NC}"
echo -e "${GREEN}║     AUTENTICAÇÃO SASL CORRIGIDA           ║${NC}"
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

# Função wait_for_apt
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

# Configurações não-interativas
echo '#!/bin/sh' > /usr/sbin/policy-rc.d
echo 'exit 101' >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

mkdir -p /etc/needrestart/conf.d/
cat > /etc/needrestart/conf.d/99-autorestart.conf << 'EOF'
$nrconf{restart} = 'a';
$nrconf{kernelhints} = -1;
EOF

apt-get update -y -qq

# Pré-configurar Postfix
echo -e "${YELLOW}Configurando Postfix...${NC}"
wait_for_apt
echo "postfix postfix/mailname string $BASE_DOMAIN" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# Instalar pacotes
echo -e "${YELLOW}Instalando pacotes...${NC}"
wait_for_apt
PACKAGES="postfix opendkim opendkim-tools dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd libsasl2-2 libsasl2-modules sasl2-bin mailutils nginx ssl-cert"

for package in $PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $package"; then
        apt-get install -y -qq $package -o Dpkg::Options::="--force-confdef" 2>/dev/null && \
            echo -e "${GREEN}✓ $package${NC}" || echo -e "${RED}✗ $package${NC}"
    fi
done

# Criar diretórios
mkdir -p /var/www/html /etc/nginx/sites-{available,enabled} /var/mail/vhosts/$BASE_DOMAIN /etc/opendkim/keys/$BASE_DOMAIN
rm -f /usr/sbin/policy-rc.d

# Hostname
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
# POSTFIX - CORRIGIDO PARA AUTENTICAÇÃO
# ====================================
echo -e "${YELLOW}Configurando Postfix com SASL...${NC}"
cat > /etc/postfix/main.cf << EOF
# Identificação
smtpd_banner = \$myhostname ESMTP
smtp_address_preference = ipv4
biff = no
compatibility_level = 2

# Domínios
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

# Restrições de relay - CRÍTICO PARA AUTENTICAÇÃO
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination

# TLS/SSL
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

# DKIM
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

# SASL - AUTENTICAÇÃO CORRIGIDA
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
broken_sasl_auth_clients = yes

# Virtual domains
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = $BASE_DOMAIN
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# Limites
message_size_limit = 52428800
mailbox_size_limit = 0

# Segurança adicional
smtpd_helo_required = yes
smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname

# Cliente restrições
smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated

# Sender restrições
smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated

# Recipient restrições
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_invalid_recipient_domain, reject_non_fqdn_recipient
EOF

echo "$BASE_DOMAIN" > /etc/mailname

# Master.cf - CORRIGIDO COM SUBMISSION
cat > /etc/postfix/master.cf << 'EOFMASTER'
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd

# Submission (porta 587) - REQUER AUTENTICAÇÃO
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
# DOVECOT - AUTENTICAÇÃO CORRIGIDA
# ====================================
echo -e "${YELLOW}Configurando Dovecot com autenticação...${NC}"
groupadd -g 5000 vmail 2>/dev/null || true
useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m 2>/dev/null || true

cat > /etc/dovecot/dovecot.conf << EOFDOVE
# Protocolos
protocols = imap pop3 lmtp

# Mail location
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail
first_valid_uid = 5000
last_valid_uid = 5000

# SSL/TLS
ssl = yes
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_min_protocol = TLSv1.2

# Autenticação - CRÍTICO
auth_mechanisms = plain login
disable_plaintext_auth = no
auth_username_format = %Ln

# LMTP service - para entrega de email
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
  user = vmail
}

# Auth service - CRÍTICO PARA SMTP
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

# Configuração de senha
passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/users
}

# Configuração de usuário
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n allow_all_users=yes
}

# Logging
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log
debug_log_path = /var/log/dovecot-debug.log
auth_verbose = yes
auth_debug = yes
mail_debug = yes

# Namespace
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

# Criar arquivo de log do Dovecot
touch /var/log/dovecot.log /var/log/dovecot-info.log /var/log/dovecot-debug.log
chown dovecot:dovecot /var/log/dovecot*.log

# ====================================
# CRIAR MÚLTIPLOS USUÁRIOS
# ====================================
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}     CRIANDO USUÁRIOS DE EMAIL${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}\n"

# Lista de usuários (usuario:senha)
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
    
    # Adicionar ao Dovecot - FORMATO CORRETO
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
# REINICIAR SERVIÇOS
# ====================================
echo -e "${YELLOW}Iniciando serviços...${NC}"

# Parar serviços primeiro
systemctl stop opendkim postfix dovecot 2>/dev/null

# Limpar sockets antigos
rm -f /var/spool/postfix/private/auth
rm -f /var/spool/postfix/private/dovecot-lmtp

# Iniciar serviços na ordem correta
systemctl start opendkim
sleep 2
systemctl start dovecot
sleep 2
systemctl start postfix

# Habilitar no boot
systemctl enable opendkim postfix dovecot 2>/dev/null

# Verificar status
echo -e "\n${YELLOW}Verificando status dos serviços...${NC}"
for service in opendkim dovecot postfix; do
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}✓ $service está rodando${NC}"
    else
        echo -e "${RED}✗ $service NÃO está rodando${NC}"
        systemctl status $service --no-pager -l
    fi
done

# Verificar socket de autenticação
echo -e "\n${YELLOW}Verificando socket de autenticação...${NC}"
if [ -S /var/spool/postfix/private/auth ]; then
    echo -e "${GREEN}✓ Socket de autenticação criado${NC}"
    ls -la /var/spool/postfix/private/auth
else
    echo -e "${RED}✗ Socket de autenticação NÃO encontrado${NC}"
fi

# ====================================
# NGINX
# ====================================
echo -e "${YELLOW}Configurando Nginx...${NC}"

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
fi

# ====================================
# PÁGINA HTML COM CONFIGURAÇÕES DNS
# ====================================
DKIM_KEY=$(cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')

echo -e "${YELLOW}Criando página de configurações DNS...${NC}"

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

cat > /var/www/html/index.html << EOFHTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuração SMTP - $BASE_DOMAIN</title>
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
            <p style="margin: 10px 0;"><strong>Domínio:</strong> $FULL_DOMAIN</p>
            <div class="ip-display">🌐 IP do Servidor: $PUBLIC_IP</div>
            <p style="margin-top: 10px;"><strong>Total de usuários criados:</strong> $CONTADOR</p>
            <p style="margin-top: 5px; color: #666;"><small>🔐 DKIM: 1024 bits | Autenticação SASL: ✓</small></p>
        </div>

        <div class="success-msg">
            <strong>✅ Instalação concluída com autenticação SASL configurada!</strong>
            <p style="margin-top: 8px;">Todos os serviços foram configurados. Configure os DNS e teste a autenticação.</p>
        </div>

        <!-- CONFIGURAÇÕES DE AUTENTICAÇÃO -->
        <div class="auth-config">
            <h3>🔐 CONFIGURAÇÃO DE AUTENTICAÇÃO SMTP</h3>
            <p><strong>IMPORTANTE:</strong> Use estas configurações no seu cliente de email:</p>
            <ul style="margin-top: 15px; margin-left: 20px;">
                <li><strong>Servidor SMTP:</strong> <code>$FULL_DOMAIN</code></li>
                <li><strong>Porta:</strong> <code>587</code> (submission - RECOMENDADO) ou <code>25</code></li>
                <li><strong>Tipo de segurança:</strong> STARTTLS (porta 587) ou Nenhum (porta 25)</li>
                <li><strong>Requer autenticação:</strong> SIM ✓</li>
                <li><strong>Nome de usuário:</strong> Email completo (ex: admin@$BASE_DOMAIN)</li>
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
                <li><strong>IP detectado:</strong> <code>$PUBLIC_IP</code> - Verifique se está correto!</li>
                <li>Configure TODOS os registros DNS abaixo</li>
                <li>Aguarde de 1 a 6 horas para propagação DNS</li>
                <li>Teste autenticação SMTP na porta 587 com STARTTLS</li>
                <li>Verifique logs em: <code>/var/log/mail.log</code></li>
            </ul>
        </div>

        <!-- USUÁRIOS CRIADOS -->
        <div class="dns-card">
            <span class="dns-type">👥 USUÁRIOS DE EMAIL CRIADOS ($CONTADOR)</span>
            <div class="info-grid">$USERS_HTML
            </div>
        </div>

        <!-- CONFIGURAÇÕES DE SERVIDOR -->
        <div class="dns-card">
            <span class="dns-type">📧 CONFIGURAÇÕES DO SERVIDOR DE EMAIL</span>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Servidor SMTP (Envio)</strong>
                    <span>$FULL_DOMAIN</span>
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
                    <strong>Servidor IMAP (Recebimento)</strong>
                    <span>$FULL_DOMAIN</span>
                </div>
                <div class="info-item">
                    <strong>Porta IMAP</strong>
                    <span>143</span>
                </div>
                <div class="info-item">
                    <strong>Servidor POP3</strong>
                    <span>$FULL_DOMAIN</span>
                </div>
                <div class="info-item">
                    <strong>Porta POP3</strong>
                    <span>110</span>
                </div>
            </div>
        </div>

        <!-- REGISTRO A -->
        <div class="dns-card">
            <span class="dns-type">🔵 Registro A (Configure primeiro!)</span>
            <div class="dns-field">
                <strong>Tipo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'A')">A</div>
            </div>
            <div class="dns-field">
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '$SUBDOMAIN')">$SUBDOMAIN</div>
            </div>
            <div class="dns-field">
                <strong>Aponta para (IP):</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '$PUBLIC_IP')">$PUBLIC_IP</div>
            </div>
            <div class="dns-field">
                <strong>TTL:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '3600')">3600</div>
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
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '@')">@</div>
            </div>
            <div class="dns-field">
                <strong>Aponta para:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '$FULL_DOMAIN')">$FULL_DOMAIN</div>
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
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '@')">@</div>
            </div>
            <div class="dns-field">
                <strong>Valor:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all')">v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all</div>
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
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '$SUBDOMAIN._domainkey')">$SUBDOMAIN._domainkey</div>
            </div>
            <div class="dns-field">
                <strong>Valor:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'v=DKIM1; k=rsa; p=$DKIM_KEY')">v=DKIM1; k=rsa; p=$DKIM_KEY</div>
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
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '_dmarc')">_dmarc</div>
            </div>
            <div class="dns-field">
                <strong>Valor:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'v=DMARC1; p=quarantine; rua=mailto:admin@$BASE_DOMAIN; aspf=r; adkim=r')">v=DMARC1; p=quarantine; rua=mailto:admin@$BASE_DOMAIN; aspf=r; adkim=r</div>
            </div>
        </div>

        <!-- TESTES -->
        <div class="dns-card" style="background: #fff3e0; border-left: 4px solid #ff9800;">
            <h2 style="color: #e65100; margin-bottom: 15px;">🧪 TESTE SUA CONFIGURAÇÃO</h2>
            <p style="margin-bottom: 15px;"><strong>Comandos para testar autenticação SMTP:</strong></p>
            <div style="background: #263238; color: #aed581; padding: 15px; border-radius: 8px; font-family: monospace; margin-bottom: 15px;">
# Teste de conexão SMTP<br>
telnet $FULL_DOMAIN 25<br>
<br>
# Teste autenticação na porta 587<br>
openssl s_client -connect $FULL_DOMAIN:587 -starttls smtp<br>
<br>
# Ver logs em tempo real<br>
tail -f /var/log/mail.log
            </div>
            <p><strong>Sites para teste:</strong></p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li><a href="https://www.mail-tester.com" target="_blank">Mail Tester</a> - Teste completo de email</li>
                <li><a href="https://mxtoolbox.com" target="_blank">MX Toolbox</a> - Verificar DNS e SPF/DKIM</li>
                <li><a href="https://dnschecker.org" target="_blank">DNS Checker</a> - Verificar propagação DNS</li>
            </ul>
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
            }).catch(err => {
                alert('Erro ao copiar.');
            });
        }
    </script>
</body>
</html>
EOFHTML

# ====================================
# TESTE DE AUTENTICAÇÃO
# ====================================
echo -e "\n${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}     TESTE DE AUTENTICAÇÃO SMTP         ${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}\n"

# Pegar primeiro usuário para teste
TEST_USER=$(echo "${USUARIOS[0]}" | cut -d':' -f1)
TEST_PASS=$(echo "${USUARIOS[0]}" | cut -d':' -f2)
TEST_EMAIL="$TEST_USER@$BASE_DOMAIN"

echo -e "${YELLOW}Testando autenticação para: $TEST_EMAIL${NC}\n"

# Verificar se o usuário existe no arquivo
if grep -q "$TEST_EMAIL" /etc/dovecot/users; then
    echo -e "${GREEN}✓ Usuário encontrado em /etc/dovecot/users${NC}"
else
    echo -e "${RED}✗ Usuário NÃO encontrado em /etc/dovecot/users${NC}"
fi

# Verificar socket
if [ -S /var/spool/postfix/private/auth ]; then
    echo -e "${GREEN}✓ Socket de autenticação existe${NC}"
    ls -la /var/spool/postfix/private/auth
else
    echo -e "${RED}✗ Socket de autenticação NÃO existe${NC}"
fi

# ====================================
# RESUMO FINAL
# ====================================
echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       INSTALAÇÃO CONCLUÍDA!                ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Domínio: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}║ IP: ${YELLOW}$PUBLIC_IP${NC}"
echo -e "${GREEN}║ Usuários: ${YELLOW}$CONTADOR${NC}"
echo -e "${GREEN}║ Autenticação SASL: ${YELLOW}✓ Configurada${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ 🌐 Acesse: ${CYAN}http://$PUBLIC_IP${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}📧 CONFIGURAÇÃO DO CLIENTE DE EMAIL:${NC}"
echo -e "  ${GREEN}Servidor SMTP:${NC} $FULL_DOMAIN"
echo -e "  ${GREEN}Porta:${NC} 587 (recomendado) ou 25"
echo -e "  ${GREEN}Segurança:${NC} STARTTLS (porta 587)"
echo -e "  ${GREEN}Autenticação:${NC} SIM (obrigatória)"
echo -e "  ${GREEN}Usuário:${NC} email completo (ex: admin@$BASE_DOMAIN)"
echo -e "  ${GREEN}Senha:${NC} a senha do usuário\n"

echo -e "${YELLOW}⚙️ COMANDOS ÚTEIS:${NC}"
echo -e "  Ver logs: ${CYAN}tail -f /var/log/mail.log${NC}"
echo -e "  Status: ${CYAN}systemctl status postfix dovecot${NC}"
echo -e "  Testar SMTP: ${CYAN}telnet $FULL_DOMAIN 25${NC}"
echo -e "  Recarregar: ${CYAN}systemctl reload postfix dovecot${NC}\n"

# Salvar resumo
cat > /root/smtp-auth-summary.txt << EOFSUMMARY
════════════════════════════════════════════════════════
        CONFIGURAÇÃO SMTP COM AUTENTICAÇÃO
════════════════════════════════════════════════════════

Data: $(date)
Domínio: $FULL_DOMAIN
IP: $PUBLIC_IP
Usuários: $CONTADOR

CONFIGURAÇÃO DO CLIENTE:
- Servidor SMTP: $FULL_DOMAIN
- Porta: 587 (STARTTLS recomendado) ou 25
- Autenticação: Obrigatória
- Usuário: email completo (ex: admin@$BASE_DOMAIN)
- Senha: a senha do usuário

USUÁRIOS CRIADOS:
EOFSUMMARY

for usuario in "${USUARIOS[@]}"; do
    USERNAME=$(echo "$usuario" | cut -d':' -f1)
    SENHA=$(echo "$usuario" | cut -d':' -f2)
    echo "$USERNAME@$BASE_DOMAIN : $SENHA" >> /root/smtp-auth-summary.txt
done

cat >> /root/smtp-auth-summary.txt << EOFSUMMARY2

COMANDOS ÚTEIS:
- Ver logs: tail -f /var/log/mail.log
- Status: systemctl status postfix dovecot
- Testar SMTP: telnet $FULL_DOMAIN 25
- Recarregar: systemctl reload postfix dovecot

ARQUIVOS IMPORTANTES:
- Configuração Postfix: /etc/postfix/main.cf
- Configuração Dovecot: /etc/dovecot/dovecot.conf
- Usuários: /etc/dovecot/users
- Logs: /var/log/mail.log

════════════════════════════════════════════════════════
EOFSUMMARY2

echo -e "${GREEN}✓ Resumo salvo em: ${CYAN}/root/smtp-auth-summary.txt${NC}\n"

# Limpar
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         🎉 INSTALAÇÃO FINALIZADA!          ║${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}║  Configure os DNS e teste a autenticação  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

exit 0
