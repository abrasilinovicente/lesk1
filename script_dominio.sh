#!/bin/bash

# Configurar para modo não-interativo
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

# Receber parâmetros
DOMAIN=$1
URL_OPENDKIM_CONF=$2
CLOUDFLARE_API=$3
CLOUDFLARE_EMAIL=$4

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Iniciando configuração do servidor${NC}"
echo -e "${GREEN}Domínio: $DOMAIN${NC}"
echo -e "${GREEN}Modo: Instalação Automática (sem interação)${NC}"
echo -e "${GREEN}========================================${NC}"

# Configurar para não perguntar sobre reinicialização de serviços
echo '#!/bin/sh' > /usr/sbin/policy-rc.d
echo 'exit 101' >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

# Configurar needrestart para modo automático
mkdir -p /etc/needrestart/conf.d/
cat > /etc/needrestart/conf.d/99-autorestart.conf << 'EOF'
# Automatically restart services
$nrconf{restart} = 'a';
$nrconf{kernelhints} = -1;
$nrconf{ucodehints} = 0;
$nrconf{restartsessionui} = 0;
$nrconf{nagsessionui} = 0;
EOF

# Atualizar sistema sem interação
echo -e "${YELLOW}Atualizando sistema...${NC}"
apt-get update -y -qq
apt-get upgrade -y -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# Pré-configurar Postfix para instalação não-interativa
echo -e "${YELLOW}Pré-configurando Postfix...${NC}"
debconf-set-selections <<< "postfix postfix/mailname string $DOMAIN"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string $DOMAIN, localhost"
debconf-set-selections <<< "postfix postfix/relayhost string ''"

# Instalar dependências necessárias sem interação
echo -e "${YELLOW}Instalando dependências...${NC}"
apt-get install -y -qq \
    postfix \
    opendkim \
    opendkim-tools \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    dovecot-lmtpd \
    libsasl2-2 \
    libsasl2-modules \
    sasl2-bin \
    mailutils \
    wget \
    unzip \
    curl \
    certbot \
    python3-certbot-nginx \
    nginx \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    2>/dev/null

# Remover policy-rc.d após instalação
rm -f /usr/sbin/policy-rc.d

# Configurar hostname
echo -e "${YELLOW}Configurando hostname...${NC}"
hostnamectl set-hostname mail.$DOMAIN
echo "127.0.0.1 mail.$DOMAIN" >> /etc/hosts

# Baixar e configurar OpenDKIM
if [ ! -z "$URL_OPENDKIM_CONF" ]; then
    echo -e "${YELLOW}Baixando configuração do OpenDKIM...${NC}"
    wget -O /etc/opendkim.conf "$URL_OPENDKIM_CONF"
fi

# Configurar OpenDKIM com chave de 1024 bits
echo -e "${YELLOW}Configurando OpenDKIM com chave RSA 1024...${NC}"
mkdir -p /etc/opendkim/keys/$DOMAIN
cd /etc/opendkim/keys/$DOMAIN
opendkim-genkey -b 1024 -s mail -d $DOMAIN
chown opendkim:opendkim mail.private
chmod 600 mail.private

# Criar arquivos de configuração OpenDKIM
echo "mail._domainkey.$DOMAIN $DOMAIN:mail:/etc/opendkim/keys/$DOMAIN/mail.private" >> /etc/opendkim/KeyTable
echo "*@$DOMAIN mail._domainkey.$DOMAIN" >> /etc/opendkim/SigningTable
echo "127.0.0.1" >> /etc/opendkim/TrustedHosts
echo "localhost" >> /etc/opendkim/TrustedHosts
echo ".$DOMAIN" >> /etc/opendkim/TrustedHosts

# Criar e configurar Postfix main.cf
echo -e "${YELLOW}Configurando Postfix main.cf...${NC}"
cat > /etc/postfix/main.cf << EOF
# =================================================================
# Arquivo de Configuração Otimizado para Postfix (main.cf)
# Configurado automaticamente para $DOMAIN
# =================================================================

# --- Configurações Gerais ---
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
smtp_address_preference = ipv4
biff = no
append_dot_mydomain = no
readme_directory = no
recipient_delimiter = +
mailbox_size_limit = 0
compatibility_level = 2

# --- Configurações de Identidade do Servidor ---
myhostname = mail.$DOMAIN
mydomain = $DOMAIN
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

# Verificar e configurar certificados SSL
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo -e "${GREEN}Certificados Let's Encrypt encontrados${NC}"
    cat >> /etc/postfix/main.cf << EOF
smtpd_tls_cert_file = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/$DOMAIN/privkey.pem
EOF
else
    echo -e "${YELLOW}Usando certificados temporários (snake oil)${NC}"
    cat >> /etc/postfix/main.cf << EOF
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
EOF
fi

# Continuar configuração do Postfix
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
smtpd_sasl_local_domain = $DOMAIN
broken_sasl_auth_clients = yes

# --- VIRTUAL MAILBOX PARA DOVECOT ---
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = $DOMAIN
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

# Criar arquivo /etc/mailname
echo "$DOMAIN" > /etc/mailname

# Criar arquivo master.cf atualizado
echo -e "${YELLOW}Configurando master.cf...${NC}"
cat > /etc/postfix/master.cf << 'EOF'
#
# Postfix master process configuration file
#
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
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m

# Criar diretórios necessários
mkdir -p /var/mail/vhosts/$DOMAIN
chown -R vmail:vmail /var/mail/vhosts

# Configurar virtual mailbox
echo "admin@$DOMAIN $DOMAIN/admin/" > /etc/postfix/vmailbox
postmap /etc/postfix/vmailbox

# Configurar Dovecot
echo -e "${YELLOW}Configurando Dovecot...${NC}"

# Configuração principal do Dovecot
cat > /etc/dovecot/dovecot.conf << EOF
# Dovecot configuration
protocols = imap pop3 lmtp
listen = *, ::
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail

# SSL/TLS
ssl = yes
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key

# Authentication
auth_mechanisms = plain login
disable_plaintext_auth = no

# Mail
first_valid_uid = 5000
last_valid_uid = 5000
first_valid_gid = 5000
last_valid_gid = 5000

# Logging
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log

# Namespaces
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

# Protocols
protocol imap {
  mail_max_userip_connections = 100
}

protocol pop3 {
  mail_max_userip_connections = 10
}

protocol lmtp {
  mail_plugins = quota
  postmaster_address = postmaster@$DOMAIN
}

# Services
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

# Passdb and Userdb
passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/users
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n allow_all_users=yes
}
EOF

# Criar arquivo de usuários do Dovecot com a senha especificada
echo -e "${YELLOW}Criando usuário admin@$DOMAIN...${NC}"
echo "admin@$DOMAIN:{PLAIN}dwwzyd" > /etc/dovecot/users
chmod 640 /etc/dovecot/users
chown root:dovecot /etc/dovecot/users

# Criar diretório do usuário admin
mkdir -p /var/mail/vhosts/$DOMAIN/admin
chown -R vmail:vmail /var/mail/vhosts/$DOMAIN/admin

# Reiniciar serviços
echo -e "${YELLOW}Reiniciando serviços...${NC}"
systemctl restart opendkim
systemctl restart postfix
systemctl restart dovecot

# Habilitar serviços na inicialização
systemctl enable opendkim
systemctl enable postfix
systemctl enable dovecot

# Configurar Nginx (básico para servir a página lesk.html)
echo -e "${YELLOW}Configurando Nginx...${NC}"
cat > /etc/nginx/sites-available/mail.$DOMAIN << EOF
server {
    listen 80;
    server_name mail.$DOMAIN $PUBLIC_IP;
    root /var/www/html;
    index index.html index.htm lesk.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -sf /etc/nginx/sites-available/mail.$DOMAIN /etc/nginx/sites-enabled/
systemctl restart nginx

# Configurar Cloudflare se as credenciais foram fornecidas
if [ ! -z "$CLOUDFLARE_API" ] && [ ! -z "$CLOUDFLARE_EMAIL" ]; then
    echo -e "${YELLOW}Configurando DNS no Cloudflare...${NC}"
    
    # Obter IP público
    PUBLIC_IP=$(curl -s ifconfig.me)
    
    # Aqui você pode adicionar a lógica para criar registros DNS via API do Cloudflare
    # Exemplo: criar registro A para mail.$DOMAIN apontando para $PUBLIC_IP
fi

# Exibir chave DKIM
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Configuração concluída!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Chave DKIM pública (adicione ao DNS):${NC}"
cat /etc/opendkim/keys/$DOMAIN/mail.txt

# Testar configuração
echo -e "${YELLOW}Testando configurações...${NC}"
postfix check
dovecot -n > /dev/null 2>&1 && echo -e "${GREEN}Dovecot: OK${NC}" || echo -e "${RED}Dovecot: ERRO${NC}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Usuário SMTP criado:${NC}"
echo -e "${GREEN}Email: admin@$DOMAIN${NC}"
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

# Log de instalação
echo "Instalação concluída em $(date)" >> /var/log/mail-setup.log
echo "Domínio: $DOMAIN" >> /var/log/mail-setup.log
echo "Usuário: admin@$DOMAIN" >> /var/log/mail-setup.log

# Obter IP público
PUBLIC_IP=$(curl -s ifconfig.me)

# Extrair chave DKIM pública
DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN/mail.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')

# Criar página HTML com configurações DNS
echo -e "${YELLOW}Criando página de configuração DNS...${NC}"
cat > /var/www/html/lesk.html << EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurações DNS - $DOMAIN</title>
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
            <h1>⚙️ Configurações DNS</h1>
            <p>Domínio: $DOMAIN</p>
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
                    <span>mail.$DOMAIN</span>
                </div>
                <div class="info-item">
                    <strong>Usuário SMTP:</strong>
                    <span>admin@$DOMAIN</span>
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
                    mail
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
                <p>Este registro aponta o subdomínio mail.$DOMAIN para o IP do seu servidor. É essencial para que o servidor de email seja encontrado.</p>
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
                    mail.$DOMAIN
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
                <p>Define qual servidor é responsável por receber emails para o domínio $DOMAIN. A prioridade 10 é padrão para servidor principal.</p>
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
                    v=spf1 ip4:$PUBLIC_IP ~all
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
                <p>SPF (Sender Policy Framework) autoriza o IP $PUBLIC_IP a enviar emails em nome do domínio $DOMAIN, ajudando a prevenir spoofing.</p>
            </div>
        </div>

        <!-- Registro DKIM -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (DKIM)</span>
            <span class="status-badge status-recommended">Recomendado</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    mail._domainkey
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    v=DKIM1; k=rsa; p=$DKIM_KEY
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
                <p>DKIM adiciona uma assinatura digital aos emails enviados, provando que são autênticos e não foram modificados. Chave RSA de 1024 bits.</p>
            </div>
        </div>

        <!-- Registro DMARC -->
        <div class="dns-card">
            <span class="dns-type">TIPO TXT (DMARC)</span>
            <span class="status-badge status-recommended">Recomendado</span>
            <div class="dns-info">
                <div class="dns-label">Nome:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    _dmarc
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Conteúdo:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    v=DMARC1; p=quarantine; rua=mailto:admin@$DOMAIN; ruf=mailto:admin@$DOMAIN; fo=1; adkim=r; aspf=r; pct=100; rf=afrf; sp=quarantine
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
                <p>DMARC define políticas de como lidar com emails que falham nas verificações SPF/DKIM. Configurado para quarentena com relatórios para admin@$DOMAIN.</p>
            </div>
        </div>

        <!-- Registro PTR (Reverso) -->
        <div class="dns-card">
            <span class="dns-type">TIPO PTR (Reverso)</span>
            <span class="status-badge status-optional">Opcional</span>
            <div class="dns-info">
                <div class="dns-label">IP Reverso:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    $PUBLIC_IP
                    <button class="copy-btn">Copiar</button>
                </div>
                <div class="dns-label">Aponta para:</div>
                <div class="dns-value" onclick="copyToClipboard(this)">
                    mail.$DOMAIN
                    <button class="copy-btn">Copiar</button>
                </div>
            </div>
            <div class="info-box">
                <h3>ℹ️ Sobre o Registro PTR</h3>
                <p>O registro PTR (DNS reverso) deve ser configurado com seu provedor de hospedagem/ISP. Melhora a reputação do servidor de email.</p>
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
                    mail.$DOMAIN
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
                <p>Permite que clientes de email (Outlook, Thunderbird) configurem automaticamente as configurações do servidor.</p>
            </div>
        </div>

        <button class="copy-all-btn" onclick="copyAllConfigs()">📋 Copiar Todas as Configurações</button>
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
=== CONFIGURAÇÕES DNS PARA $DOMAIN ===

REGISTRO A:
Nome: mail
Conteúdo: $PUBLIC_IP
TTL: 3600

REGISTRO MX:
Nome: @
Servidor: mail.$DOMAIN
Prioridade: 10
TTL: 3600

REGISTRO SPF (TXT):
Nome: @
Conteúdo: v=spf1 ip4:$PUBLIC_IP ~all
TTL: 3600

REGISTRO DKIM (TXT):
Nome: mail._domainkey
Conteúdo: v=DKIM1; k=rsa; p=$DKIM_KEY
TTL: 3600

REGISTRO DMARC (TXT):
Nome: _dmarc
Conteúdo: v=DMARC1; p=quarantine; rua=mailto:admin@$DOMAIN; ruf=mailto:admin@$DOMAIN; fo=1; adkim=r; aspf=r; pct=100; rf=afrf; sp=quarantine
TTL: 3600

REGISTRO PTR (Reverso):
IP: $PUBLIC_IP → mail.$DOMAIN
(Configurar com provedor de hospedagem)

REGISTRO AUTODISCOVER (CNAME):
Nome: autodiscover
Aponta para: mail.$DOMAIN
TTL: 3600

=== INFORMAÇÕES DO SERVIDOR ===
IP: $PUBLIC_IP
Hostname: mail.$DOMAIN
Usuário SMTP: admin@$DOMAIN
Senha: dwwzyd
Portas: 25, 587, 465 (SMTP) | 143, 993 (IMAP) | 110, 995 (POP3)
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

        // Adicionar efeito de fade-in ao carregar
        document.addEventListener('DOMContentLoaded', () => {
            const cards = document.querySelectorAll('.dns-card, .server-info');
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
echo -e "${GREEN}Página de configuração DNS criada!${NC}"
echo -e "${GREEN}Acesse: http://$PUBLIC_IP/lesk.html${NC}"
echo -e "${GREEN}========================================${NC}"

# Limpar configurações temporárias
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

exit 0
