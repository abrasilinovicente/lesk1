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
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   INSTALADOR SMTP - MULTI-USUÁRIO v3.0   ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Domínio: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}║ Subdomínio: ${YELLOW}$SUBDOMAIN${NC}"
echo -e "${GREEN}║ Base: ${YELLOW}$BASE_DOMAIN${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

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
# OPENDKIM - 2048 BITS
# ====================================
echo -e "${YELLOW}Gerando chave DKIM 2048 bits...${NC}"
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
opendkim-genkey -b 2048 -s $SUBDOMAIN -d $BASE_DOMAIN 2>/dev/null || opendkim-genkey -b 2048 -s $SUBDOMAIN -d $BASE_DOMAIN

if [ -f $SUBDOMAIN.private ]; then
    echo -e "${GREEN}✓ Chave DKIM 2048 bits gerada!${NC}"
    chown opendkim:opendkim $SUBDOMAIN.private
    chmod 600 $SUBDOMAIN.private
else
    echo -e "${RED}✗ Erro! Usando método alternativo...${NC}"
    openssl genrsa -out $SUBDOMAIN.private 2048
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
# CRIAR MÚLTIPLOS USUÁRIOS - SOLUÇÃO 1
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
PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "SEU_IP")

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
# PÁGINA HTML COM LISTA DE USUÁRIOS
# ====================================
DKIM_KEY=$(cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')

echo -e "${YELLOW}Criando página DNS...${NC}"

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
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 15px;
        }
        .dns-value {
            background: #f5f5f5;
            padding: 8px 15px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            word-break: break-all;
            cursor: pointer;
            margin: 5px 0;
        }
        .dns-value:hover { background: #e8e8e8; }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
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
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚙️ Configuração SMTP</h1>
            <p><strong>Domínio:</strong> $FULL_DOMAIN</p>
            <p><strong>IP:</strong> $PUBLIC_IP</p>
            <p><strong>Total de usuários:</strong> $CONTADOR</p>
        </div>

        <div class="warning">
            <strong>⚠️ IMPORTANTE:</strong>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>Use <code>~all</code> no SPF (NÃO use <code>-all</code>)</li>
                <li>Aguarde 1-6 horas para propagação DNS</li>
                <li>Teste em <a href="https://www.mail-tester.com" target="_blank">mail-tester.com</a></li>
            </ul>
        </div>

        <!-- USUÁRIOS CRIADOS -->
        <div class="dns-card">
            <span class="dns-type">👥 USUÁRIOS CRIADOS</span>
            <div class="info-grid">$USERS_HTML
            </div>
        </div>

        <!-- SPF -->
        <div class="dns-card">
            <span class="dns-type">SPF (CRÍTICO!)</span>
            <p><strong>Tipo:</strong> TXT</p>
            <p><strong>Nome:</strong> @</p>
            <p><strong>Valor:</strong></p>
            <div class="dns-value" onclick="copyToClipboard(this)">v=spf1 ip4:$PUBLIC_IP a:$FULL_DOMAIN ~all</div>
            <p style="margin-top:10px;color:#666;"><small>⚠️ Use ~all (NÃO -all!)</small></p>
        </div>

        <!-- DKIM -->
        <div class="dns-card">
            <span class="dns-type">DKIM (CRÍTICO!)</span>
            <p><strong>Tipo:</strong> TXT</p>
            <p><strong>Nome:</strong> $SUBDOMAIN._domainkey</p>
            <p><strong>Valor:</strong></p>
            <div class="dns-value" onclick="copyToClipboard(this)">v=DKIM1; k=rsa; p=$DKIM_KEY</div>
            <p style="margin-top:10px;color:#666;"><small>🔐 Chave RSA 2048 bits</small></p>
        </div>

        <!-- DMARC -->
        <div class="dns-card">
            <span class="dns-type">DMARC</span>
            <p><strong>Tipo:</strong> TXT</p>
            <p><strong>Nome:</strong> _dmarc</p>
            <p><strong>Valor:</strong></p>
            <div class="dns-value" onclick="copyToClipboard(this)">v=DMARC1; p=quarantine; rua=mailto:admin@$BASE_DOMAIN; aspf=r; adkim=r</div>
        </div>

        <!-- MX -->
        <div class="dns-card">
            <span class="dns-type">MX (Obrigatório)</span>
            <p><strong>Tipo:</strong> MX</p>
            <p><strong>Nome:</strong> @</p>
            <p><strong>Servidor:</strong> $FULL_DOMAIN</p>
            <p><strong>Prioridade:</strong> 10</p>
        </div>

        <!-- Registro A -->
        <div class="dns-card">
            <span class="dns-type">Registro A</span>
            <p><strong>Tipo:</strong> A</p>
            <p><strong>Nome:</strong> $SUBDOMAIN</p>
            <p><strong>IP:</strong> $PUBLIC_IP</p>
        </div>

    </div>

    <script>
        function copyToClipboard(element) {
            const text = element.textContent.trim();
            navigator.clipboard.writeText(text).then(() => {
                const original = element.style.background;
                element.style.background = '#4caf50';
                setTimeout(() => element.style.background = original, 1000);
            });
        }
    </script>
</body>
</html>
EOFHTML

# ====================================
# RESUMO FINAL
# ====================================
echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       INSTALAÇÃO CONCLUÍDA COM SUCESSO!    ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Domínio: ${YELLOW}$FULL_DOMAIN${NC}"
echo -e "${GREEN}║ IP: ${YELLOW}$PUBLIC_IP${NC}"
echo -e "${GREEN}║ Usuários: ${YELLOW}$CONTADOR${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ 📧 Acesse: ${CYAN}http://$PUBLIC_IP${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}👥 USUÁRIOS CRIADOS:${NC}\n"
for usuario in "${USUARIOS[@]}"; do
    USERNAME=$(echo "$usuario" | cut -d':' -f1)
    SENHA=$(echo "$usuario" | cut -d':' -f2)
    echo -e "  ${GREEN}✓${NC} $USERNAME@$BASE_DOMAIN (senha: $SENHA)"
done

echo -e "\n${CYAN}📋 PRÓXIMOS PASSOS:${NC}"
echo -e "  1. Acesse: ${BLUE}http://$PUBLIC_IP${NC}"
echo -e "  2. Configure DNS (SPF, DKIM, DMARC, MX, A)"
echo -e "  3. Aguarde 1-6h propagação DNS"
echo -e "  4. Teste em: ${BLUE}https://www.mail-tester.com${NC}\n"

# Log
cat >> /var/log/mail-setup.log << EOFLOG
════════════════════════════════════════
Instalação: $(date)
Domínio: $FULL_DOMAIN
IP: $PUBLIC_IP
Usuários: $CONTADOR
════════════════════════════════════════
EOFLOG

# Limpar
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

echo -e "${GREEN}🎉 Script finalizado!${NC}\n"
exit 0
