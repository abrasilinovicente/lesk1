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
echo -e "${GREEN}║   INSTALADOR SMTP - MULTI-USUÁRIO v3.1   ║${NC}"
echo -e "${GREEN}║        DKIM 1024 bits compatível          ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Domínio: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}║ Subdomínio: ${YELLOW}$SUBDOMAIN${NC}"
echo -e "${GREEN}║ Base: ${YELLOW}$BASE_DOMAIN${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

sleep 2

# ====================================
# DETECTAR IP PÚBLICO (MELHORADO)
# ====================================
echo -e "${YELLOW}Detectando IP público...${NC}"

# Tentar múltiplos serviços para detectar o IP
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

# Se não conseguiu detectar, tentar pelo hostname -I
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(hostname -I | awk '{print $1}')
    echo -e "${YELLOW}⚠ IP detectado via hostname: $PUBLIC_IP${NC}"
fi

# Validar formato do IP
if [[ ! $PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}✗ ERRO: Não foi possível detectar um IP válido!${NC}"
    echo -e "${YELLOW}Por favor, insira o IP público manualmente:${NC}"
    read -p "IP: " PUBLIC_IP
    
    # Validar novamente
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
# POSTFIX
# ====================================
echo -e "${YELLOW}Configurando Postfix...${NC}"
cat > /etc/postfix/main.cf << EOF
smtpd_banner = \$myhostname ESMTP
smtp_address_preference = ipv4
biff = no
compatibility_level = 2

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

smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination

smtpd_use_tls = yes
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level = may

milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous

virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = $BASE_DOMAIN
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

message_size_limit = 52428800
smtpd_helo_required = yes
EOF

echo "$BASE_DOMAIN" > /etc/mailname

# Master.cf
cat > /etc/postfix/master.cf << 'EOFMASTER'
smtp      inet  n       -       y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
smtp      unix  -       -       y       -       -       smtp
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
EOFMASTER

# ====================================
# DOVECOT
# ====================================
echo -e "${YELLOW}Configurando Dovecot...${NC}"
groupadd -g 5000 vmail 2>/dev/null || true
useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m 2>/dev/null || true

cat > /etc/dovecot/dovecot.conf << EOFDOVE
protocols = imap pop3 lmtp
mail_location = maildir:/var/mail/vhosts/%d/%n
first_valid_uid = 5000

ssl = yes
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key

auth_mechanisms = plain login
disable_plaintext_auth = no

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
}

passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/users
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
EOFDOVE

# ====================================
# CRIAR MÚLTIPLOS USUÁRIOS
# ====================================
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}     CRIANDO USUÁRIOS DE EMAIL${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}\n"

# Lista de usuários (usuario:senha)
# Edite aqui para adicionar/remover usuários
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
    
    # Validar
    if [ -z "$USERNAME" ] || [ -z "$SENHA" ]; then
        echo -e "${RED}✗ Usuário inválido: $usuario${NC}"
        continue
    fi
    
    # Montar email completo
    EMAIL="$USERNAME@$BASE_DOMAIN"
    
    # Adicionar ao Dovecot
    echo "$EMAIL:{PLAIN}$SENHA" >> /etc/dovecot/users
    
    # Criar diretório do usuário
    mkdir -p /var/mail/vhosts/$BASE_DOMAIN/$USERNAME
    chown -R vmail:vmail /var/mail/vhosts/$BASE_DOMAIN/$USERNAME
    
    # Adicionar ao Postfix virtual mailbox
    echo "$EMAIL $BASE_DOMAIN/$USERNAME/" >> /etc/postfix/vmailbox
    
    echo -e "${GREEN}✓ $EMAIL (senha: $SENHA)${NC}"
    CONTADOR=$((CONTADOR + 1))
done

# Configurar permissões
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
systemctl restart opendkim postfix dovecot 2>/dev/null
systemctl enable opendkim postfix dovecot 2>/dev/null

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
            <p style="margin-top: 5px; color: #666;"><small>🔐 DKIM: 1024 bits (compatível)</small></p>
        </div>

        <div class="success-msg">
            <strong>✅ Instalação concluída com sucesso!</strong>
            <p style="margin-top: 8px;">Todos os serviços foram configurados. Agora configure os registros DNS abaixo.</p>
        </div>

        <div class="warning">
            <strong>⚠️ IMPORTANTE - CONFIGURAÇÃO DNS:</strong>
            <ul>
                <li><strong>Use <code>~all</code> no SPF</strong> (NÃO use <code>-all</code> - isso pode bloquear emails)</li>
                <li><strong>IP detectado:</strong> <code>$PUBLIC_IP</code> - Verifique se está correto!</li>
                <li><strong>DKIM 1024 bits:</strong> Chave compatível com a maioria dos provedores DNS</li>
                <li>Configure TODOS os registros DNS abaixo no painel do seu domínio</li>
                <li>Aguarde de 1 a 6 horas para propagação DNS completa</li>
                <li>Teste seus emails em: <a href="https://www.mail-tester.com" target="_blank" style="color: #007bff;">mail-tester.com</a></li>
                <li>Verifique SPF/DKIM em: <a href="https://mxtoolbox.com" target="_blank" style="color: #007bff;">mxtoolbox.com</a></li>
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
                    <strong>Servidor SMTP</strong>
                    <span>$FULL_DOMAIN</span>
                </div>
                <div class="info-item">
                    <strong>Porta SMTP</strong>
                    <span>25 ou 587 (submission)</span>
                </div>
                <div class="info-item">
                    <strong>Servidor IMAP</strong>
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
            <span class="dns-type">🔵 Registro A (Obrigatório - Configure primeiro!)</span>
            <div class="dns-field">
                <strong>Tipo de Registro:</strong>
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
            <span class="dns-type">📨 Registro MX (Obrigatório)</span>
            <div class="dns-field">
                <strong>Tipo de Registro:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'MX')">MX</div>
            </div>
            <div class="dns-field">
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '@')">@</div>
            </div>
            <div class="dns-field">
                <strong>Aponta para (Mail Server):</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '$FULL_DOMAIN')">$FULL_DOMAIN</div>
            </div>
            <div class="dns-field">
                <strong>Prioridade:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '10')">10</div>
            </div>
            <div class="dns-field">
                <strong>TTL:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '3600')">3600</div>
            </div>
        </div>

        <!-- SPF -->
        <div class="dns-card">
            <span class="dns-type">🔒 SPF (CRÍTICO - Evita spam!)</span>
            <div class="dns-field">
                <strong>Tipo de Registro:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'TXT')">TXT</div>
            </div>
            <div class="dns-field">
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '@')">@</div>
            </div>
            <div class="dns-field">
                <strong>Valor/Conteúdo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all')">v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all</div>
            </div>
            <div class="dns-field">
                <strong>TTL:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '3600')">3600</div>
            </div>
            <p style="margin-top:15px;color:#dc3545;font-weight:bold;">⚠️ IMPORTANTE: Use ~all (NÃO use -all!)</p>
        </div>

        <!-- DKIM -->
        <div class="dns-card">
            <span class="dns-type">🔐 DKIM (CRÍTICO - Autenticação de email)</span>
            <div class="dns-field">
                <strong>Tipo de Registro:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'TXT')">TXT</div>
            </div>
            <div class="dns-field">
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '$SUBDOMAIN._domainkey')">$SUBDOMAIN._domainkey</div>
            </div>
            <div class="dns-field">
                <strong>Valor/Conteúdo (Chave RSA 1024 bits):</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'v=DKIM1; k=rsa; p=$DKIM_KEY')">v=DKIM1; k=rsa; p=$DKIM_KEY</div>
            </div>
            <div class="dns-field">
                <strong>TTL:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '3600')">3600</div>
            </div>
            <p style="margin-top:15px;color:#28a745;">✓ Chave DKIM gerada com 1024 bits (compatível com a maioria dos provedores)</p>
        </div>

        <!-- DMARC -->
        <div class="dns-card">
            <span class="dns-type">📋 DMARC (Recomendado)</span>
            <div class="dns-field">
                <strong>Tipo de Registro:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'TXT')">TXT</div>
            </div>
            <div class="dns-field">
                <strong>Nome/Host:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '_dmarc')">_dmarc</div>
            </div>
            <div class="dns-field">
                <strong>Valor/Conteúdo:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, 'v=DMARC1; p=quarantine; rua=mailto:admin@$BASE_DOMAIN; aspf=r; adkim=r')">v=DMARC1; p=quarantine; rua=mailto:admin@$BASE_DOMAIN; aspf=r; adkim=r</div>
            </div>
            <div class="dns-field">
                <strong>TTL:</strong>
                <div class="dns-value" onclick="copyToClipboard(this, '3600')">3600</div>
            </div>
        </div>

        <!-- INSTRUÇÕES FINAIS -->
        <div class="dns-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
            <h2 style="margin-bottom: 20px;">📝 Próximos Passos</h2>
            <ol style="margin-left: 20px; line-height: 1.8;">
                <li><strong>Configure todos os registros DNS acima</strong> no painel do seu provedor de domínio</li>
                <li><strong>Aguarde de 1 a 6 horas</strong> para propagação DNS</li>
                <li><strong>Verifique a propagação:</strong> <a href="https://dnschecker.org" target="_blank" style="color: #ffd700;">dnschecker.org</a></li>
                <li><strong>Teste seu email:</strong> Envie para <a href="https://www.mail-tester.com" target="_blank" style="color: #ffd700;">mail-tester.com</a></li>
                <li><strong>Verifique SPF/DKIM:</strong> <a href="https://mxtoolbox.com/SuperTool.aspx" target="_blank" style="color: #ffd700;">mxtoolbox.com</a></li>
                <li><strong>Configure seu cliente de email</strong> (Outlook, Gmail, etc.) com as credenciais acima</li>
            </ol>
        </div>

    </div>

    <script>
        function copyToClipboard(element, text) {
            // Se text não foi fornecido, pega do elemento
            const textToCopy = text || element.textContent.trim();
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Mudar cor do elemento
                const original = element.style.background;
                const originalBorder = element.style.borderColor;
                element.style.background = '#28a745';
                element.style.borderColor = '#28a745';
                element.style.color = 'white';
                
                // Mostrar notificação
                const notification = document.getElementById('copyNotification');
                notification.style.display = 'block';
                
                setTimeout(() => {
                    element.style.background = original;
                    element.style.borderColor = originalBorder;
                    element.style.color = '';
                    notification.style.display = 'none';
                }, 1500);
            }).catch(err => {
                alert('Erro ao copiar. Use Ctrl+C para copiar manualmente.');
            });
        }
    </script>
</body>
</html>
EOFHTML

# ====================================
# RESUMO FINAL NO TERMINAL
# ====================================
echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       INSTALAÇÃO CONCLUÍDA COM SUCESSO!    ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Domínio: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}║ IP Detectado: ${YELLOW}$PUBLIC_IP${NC}"
echo -e "${GREEN}║ Usuários criados: ${YELLOW}$CONTADOR${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ 📧 Acesse: ${CYAN}http://$PUBLIC_IP${NC}"
echo -e "${GREEN}║ 🌐 ou: ${CYAN}http://$FULL_DOMAIN${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}┌─────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│         👥 USUÁRIOS CRIADOS             │${NC}"
echo -e "${CYAN}└─────────────────────────────────────────┘${NC}\n"

for usuario in "${USUARIOS[@]}"; do
    USERNAME=$(echo "$usuario" | cut -d':' -f1)
    SENHA=$(echo "$usuario" | cut -d':' -f2)
    printf "${GREEN}  ✓${NC} %-30s ${YELLOW}%s${NC}\n" "$USERNAME@$BASE_DOMAIN" "(senha: $SENHA)"
done

echo -e "\n${CYAN}┌─────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│       📋 CONFIGURAÇÕES DNS              │${NC}"
echo -e "${CYAN}└─────────────────────────────────────────┘${NC}\n"

echo -e "${YELLOW}1. Registro A:${NC}"
echo -e "   Nome: ${CYAN}$SUBDOMAIN${NC}"
echo -e "   IP: ${GREEN}$PUBLIC_IP${NC}\n"

echo -e "${YELLOW}2. Registro MX:${NC}"
echo -e "   Nome: ${CYAN}@${NC}"
echo -e "   Servidor: ${CYAN}$FULL_DOMAIN${NC}"
echo -e "   Prioridade: ${CYAN}10${NC}\n"

echo -e "${YELLOW}3. SPF (TXT):${NC}"
echo -e "   Nome: ${CYAN}@${NC}"
echo -e "   Valor: ${GREEN}v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all${NC}\n"

echo -e "${YELLOW}4. DKIM (TXT):${NC}"
echo -e "   Nome: ${CYAN}$SUBDOMAIN._domainkey${NC}"
echo -e "   (Veja a chave completa na página web)\n"

echo -e "${YELLOW}5. DMARC (TXT):${NC}"
echo -e "   Nome: ${CYAN}_dmarc${NC}"
echo -e "   (Veja o valor completo na página web)\n"

echo -e "${CYAN}📝 PRÓXIMOS PASSOS:${NC}"
echo -e "  ${GREEN}1.${NC} Acesse: ${BLUE}http://$PUBLIC_IP${NC}"
echo -e "  ${GREEN}2.${NC} Configure todos os registros DNS listados"
echo -e "  ${GREEN}3.${NC} Aguarde 1-6h para propagação DNS"
echo -e "  ${GREEN}4.${NC} Teste em: ${BLUE}https://www.mail-tester.com${NC}"
echo -e "  ${GREEN}5.${NC} Verifique em: ${BLUE}https://mxtoolbox.com${NC}\n"

# Log detalhado
cat >> /var/log/mail-setup.log << EOFLOG
════════════════════════════════════════
Instalação: $(date)
Domínio: $FULL_DOMAIN
Subdomínio: $SUBDOMAIN
Domínio Base: $BASE_DOMAIN
IP Público: $PUBLIC_IP
Usuários criados: $CONTADOR
════════════════════════════════════════
EOFLOG

# Criar arquivo com resumo das configurações
cat > /root/smtp-config-summary.txt << EOFSUMMARY
════════════════════════════════════════════════════════
        RESUMO DA CONFIGURAÇÃO SMTP
════════════════════════════════════════════════════════

Data: $(date)
Domínio: $FULL_DOMAIN
IP Público: $PUBLIC_IP
Usuários criados: $CONTADOR

════════════════════════════════════════════════════════
                 REGISTROS DNS
════════════════════════════════════════════════════════

1. REGISTRO A
   Tipo: A
   Nome: $SUBDOMAIN
   IP: $PUBLIC_IP
   TTL: 3600

2. REGISTRO MX
   Tipo: MX
   Nome: @
   Servidor: $FULL_DOMAIN
   Prioridade: 10
   TTL: 3600

3. SPF
   Tipo: TXT
   Nome: @
   Valor: v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all
   TTL: 3600

4. DKIM
   Tipo: TXT
   Nome: $SUBDOMAIN._domainkey
   Valor: v=DKIM1; k=rsa; p=$DKIM_KEY
   TTL: 3600

5. DMARC
   Tipo: TXT
   Nome: _dmarc
   Valor: v=DMARC1; p=quarantine; rua=mailto:admin@$BASE_DOMAIN; aspf=r; adkim=r
   TTL: 3600

════════════════════════════════════════════════════════
              USUÁRIOS DE EMAIL
════════════════════════════════════════════════════════

EOFSUMMARY

for usuario in "${USUARIOS[@]}"; do
    USERNAME=$(echo "$usuario" | cut -d':' -f1)
    SENHA=$(echo "$usuario" | cut -d':' -f2)
    echo "$USERNAME@$BASE_DOMAIN - Senha: $SENHA" >> /root/smtp-config-summary.txt
done

cat >> /root/smtp-config-summary.txt << EOFSUMMARY2

════════════════════════════════════════════════════════
        CONFIGURAÇÕES DO SERVIDOR DE EMAIL
════════════════════════════════════════════════════════

Servidor SMTP: $FULL_DOMAIN
Porta SMTP: 25 ou 587
Servidor IMAP: $FULL_DOMAIN
Porta IMAP: 143
Servidor POP3: $FULL_DOMAIN
Porta POP3: 110

════════════════════════════════════════════════════════
                 ACESSO À PÁGINA WEB
════════════════════════════════════════════════════════

http://$PUBLIC_IP
http://$FULL_DOMAIN

════════════════════════════════════════════════════════
EOFSUMMARY2

echo -e "${GREEN}✓ Resumo salvo em: ${CYAN}/root/smtp-config-summary.txt${NC}"
echo -e "${GREEN}✓ Log salvo em: ${CYAN}/var/log/mail-setup.log${NC}\n"

# Limpar
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         🎉 SCRIPT FINALIZADO!              ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

exit 0
