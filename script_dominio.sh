#!/bin/bash

set -Eeuo pipefail
trap 'echo "[ERRO] linha $LINENO: $BASH_COMMAND (status $?)" >&2' ERR

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

# Extrair domínio principal para Cloudflare
MAIN_DOMAIN=$(echo $DOMAIN | cut -d "." -f2-)
SERVER_IP=$(wget -qO- http://ip-api.com/line\?fields=query)

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

# Etapas 1-6 (Sistema, Rede, SSL)
apt-get update && apt-get upgrade -y && apt-get install -y curl unzip software-properties-common toilet ufw jq || log_error "Atualização e Pacotes Essenciais"
hostnamectl set-hostname "$DOMAIN" && echo "$DOMAIN" > /etc/hostname || log_error "Configuração de Hostname"
ufw allow 'OpenSSH' && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 25/tcp && ufw --force enable || log_error "Configuração do Firewall"
add-apt-repository ppa:ondrej/php -y && apt-get update -y || log_error "Adição do Repositório PHP"
apt-get install -y apache2 php7.4 libapache2-mod-php7.4 php7.4-cli php7.4-mysql php7.4-gd php7.4-imagick php7.4-tidy php7.4-xmlrpc php7.4-common php7.4-xml php7.4-curl php7.4-dev php7.4-imap php7.4-mbstring php7.4-opcache php7.4-soap php7.4-zip php7.4-intl --allow-unauthenticated || log_error "Instalação do Apache e PHP"
apt-get install -y certbot python3-certbot-apache && a2enmod rewrite ssl && systemctl restart apache2 && certbot --apache --non-interactive --agree-tos -m "admin@$DOMAIN" -d "$DOMAIN" || log_error "Instalação do Certificado SSL"

# ==============================================================================
# 7. DOWNLOAD E CONFIGURAÇÃO
# ==============================================================================
echo "-> Preparando para instalar aplicações..."
rm -f "$WEB_ROOT/index.html"

echo "-> Instalando Backend (API) no diretório home (/root/)..."
(cd /root/ && \
    echo "Baixando base.zip..." && \
    curl -L -o base.zip "$URL_APP_ZIP" && \
    echo "Extraindo base.zip..." && \
    unzip -o base.zip && \
    echo "Limpando base.zip..." && \
    rm base.zip \
) || log_error "Instalação do Backend (API)"

echo "-> Aplicando permissões..."
chmod -R 777 "$WEB_ROOT"

# ==============================================================================
# 8. CONFIGURAÇÃO DE EMAIL
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

# ==============================================================================
# 8.1. CONFIGURAÇÃO DE LOGGING DE EMAIL (CORRIGIDO)
# ==============================================================================
echo "-> Configurando logging de email..."
(
    # Instalar rsyslog se necessário
    if ! command -v rsyslogd >/dev/null 2>&1; then
        echo "-> Instalando rsyslog..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog
        systemctl enable rsyslog
        systemctl start rsyslog
    fi
    
    # Criar arquivos de log
    touch /var/log/maillog /var/log/mail.info /var/log/mail.warn /var/log/mail.err
    chmod 640 /var/log/maillog /var/log/mail.*
    chown root:root /var/log/maillog /var/log/mail.*
    
    # Configurar rsyslog se existir
    if [ -f /etc/rsyslog.conf ]; then
        if ! grep -q "mail.*" /etc/rsyslog.conf; then
            echo "mail.*                          /var/log/maillog" >> /etc/rsyslog.conf
        fi
        systemctl restart rsyslog 2>/dev/null || true
    fi
    
    echo "✅ Arquivos de log criados"
    
) || echo "⚠️ Aviso: Problema na configuração de logging (não crítico)"

# ==============================================================================
# 9. CONFIGURAÇÃO CLOUDFLARE DNS (MÉTODO SIMPLES E EFICAZ)
# ==============================================================================
if [ -n "$CLOUDFLARE_API" ] && [ -n "$CLOUDFLARE_EMAIL" ]; then
    echo "-> Configurando DNS no Cloudflare..."
    
    # Instalar jq se não existir
    if ! command -v jq &> /dev/null; then
        echo "-> Instalando jq..."
        apt-get install -y jq
    fi
    
    DKIM_FILE="/etc/opendkim/keys/default.txt"
    
    echo "-> Conteúdo do arquivo DKIM:"
    cat "$DKIM_FILE"
    echo "================================"
    
    # Usar seu método simples e eficaz
    echo "-> Extraindo código DKIM (método simples)..."
    
    # Extrair apenas a parte da chave pública
    DKIMCode=$(grep -A 10 'p=' "$DKIM_FILE" | grep -v '; -----' | tr -d '\n\r\t "()' | sed 's/.*p=//; s/;.*//; s/v=DKIM1.*//; s/h=sha256.*//; s/k=rsa.*//;')
    
    echo "-> Primeira tentativa: '${DKIMCode:0:50}...' (${#DKIMCode} chars)"
    
    # Se não funcionou, método mais direto
    if [ -z "$DKIMCode" ] || [ ${#DKIMCode} -lt 100 ]; then
        echo "-> Tentando método alternativo..."
        
        # Pegar todas as linhas com aspas, remover tudo exceto a chave
        DKIMCode=$(cat "$DKIM_FILE" | grep '"' | grep -v '; -----' | tr -d '"' | tr -d ' \t\n\r' | sed 's/.*p=//; s/v=DKIM1.*//; s/h=sha256.*//; s/k=rsa.*//;')
        
        echo "-> Segunda tentativa: '${DKIMCode:0:50}...' (${#DKIMCode} chars)"
    fi
    
    # Se ainda não funcionou, método de força bruta
    if [ -z "$DKIMCode" ] || [ ${#DKIMCode} -lt 100 ]; then
        echo "-> Método de força bruta..."
        
        # Extrair tudo que parece ser Base64 após encontrar uma linha com p=
        DKIMCode=""
        FOUND_P=false
        
        while IFS= read -r line; do
            if echo "$line" | grep -q 'p='; then
                FOUND_P=true
                # Extrair a parte após p=
                temp=$(echo "$line" | sed 's/.*p=//; s/".*//; s/ //g')
                DKIMCode="$DKIMCode$temp"
            elif [ "$FOUND_P" = true ] && echo "$line" | grep -q '"'; then
                # Linha de continuação
                temp=$(echo "$line" | tr -d '"' | tr -d ' \t')
                DKIMCode="$DKIMCode$temp"
                
                # Se encontrou ), parar
                if echo "$line" | grep -q ')'; then
                    break
                fi
            fi
        done < "$DKIM_FILE"
        
        echo "-> Força bruta: '${DKIMCode:0:50}...' (${#DKIMCode} chars)"
    fi
    
    # Limpeza final usando seu método
    DKIMCode=$(echo "$DKIMCode" | tr -d '\n' | tr -s ' ')
    
    # Remover qualquer lixo conhecido
    DKIMCode=$(echo "$DKIMCode" | sed 's/[^A-Za-z0-9+\/=]//g')
    
    echo "-> Código DKIM final:"
    echo "   Tamanho: ${#DKIMCode} caracteres"
    echo "   Início: ${DKIMCode:0:50}..."
    echo "   Final: ...${DKIMCode: -50}"
    
    # Validação
    if [ ${#DKIMCode} -lt 300 ]; then
        echo "❌ ERRO: Chave DKIM muito curta (${#DKIMCode} caracteres)"
        echo "Debug do arquivo:"
        echo "=================="
        cat "$DKIM_FILE" | nl
        echo "=================="
        exit 1
    fi
    
    # Verificar se é Base64 válido
    if echo "$DKIMCode" | grep -q '^[A-Za-z0-9+/]*=*$'; then
        echo "✅ Chave DKIM válida (${#DKIMCode} caracteres)"
    else
        echo "❌ ERRO: Chave contém caracteres inválidos"
        echo "Chave: '$DKIMCode'"
        exit 1
    fi
    
    # Escapar aspas para JSON
    EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\"/g')
    
    # Obter Zone ID
    echo "-> Obtendo Zone ID do Cloudflare para $MAIN_DOMAIN..."
    ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$MAIN_DOMAIN&status=active" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API" \
        -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
    
    if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" = "null" ]; then
        echo "⚠️ Zone ID não encontrado para $MAIN_DOMAIN"
        echo ""
        echo "=== CONFIGURAÇÃO MANUAL ==="
        echo "Nome: default._domainkey.$DOMAIN"
        echo "Tipo: TXT"
        echo "Valor: v=DKIM1; h=sha256; k=rsa; p=$DKIMCode"
        echo "=========================="
    else
        echo "✅ Zone ID obtido: $ZONE_ID"
        
        # Função para criar/atualizar registro (baseada na sua sugestão)
        create_or_update_record() {
            local name="$1"
            local type="$2"
            local content="$3"
            
            echo "-> Criando/atualizando registro $name..."
            
            # Verificar se já existe
            EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$name&type=$type" \
                -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
                -H "X-Auth-Key: $CLOUDFLARE_API" \
                -H "Content-Type: application/json")
            
            RECORD_ID=$(echo "$EXISTING" | jq -r '.result[0].id // empty')
            
            if [ -n "$RECORD_ID" ] && [ "$RECORD_ID" != "null" ]; then
                echo "-> Atualizando registro existente: $RECORD_ID"
                RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                    -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
                    -H "X-Auth-Key: $CLOUDFLARE_API" \
                    -H "Content-Type: application/json" \
                    --data "{\"type\":\"$type\",\"name\":\"$name\",\"content\":$content,\"ttl\":300}")
            else
                echo "-> Criando novo registro..."
                RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
                    -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
                    -H "X-Auth-Key: $CLOUDFLARE_API" \
                    -H "Content-Type: application/json" \
                    --data "{\"type\":\"$type\",\"name\":\"$name\",\"content\":$content,\"ttl\":300}")
            fi
            
            if echo "$RESPONSE" | jq -r '.success' | grep -q "true"; then
                echo "✅ Registro $name configurado com sucesso!"
            else
                echo "❌ Erro ao configurar $name:"
                echo "$RESPONSE" | jq -r '.errors[]?.message // "Erro desconhecido"'
            fi
        }
        
        # Criar registro DKIM usando sua função
        create_or_update_record "default._domainkey.$DOMAIN" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\""
    fi
    
    echo "✅ Configuração DNS finalizada!"
fi
# ==============================================================================
# 10. FINALIZAÇÃO
# ==============================================================================
echo "-> Configurando a mensagem de boas-vindas..."
echo 'Lesk /2025' | sudo toilet --filter metal > /etc/motd

echo ""
echo "🎉 ================= CONFIGURAÇÃO CONCLUÍDA ================= 🎉"
echo "✅ Domínio: $DOMAIN"
echo "✅ SSL: Configurado"
echo "✅ Email: Configurado"
if [ -n "$ZONE_ID" ] && [ "$ZONE_ID" != "null" ]; then
    echo "✅ DNS: Configurado automaticamente no Cloudflare"
else
    echo "⚠️ DNS: Configuração manual necessária"
    echo ""
    echo "==================== REGISTRO DKIM MANUAL ===================="
    echo "Adicione o seguinte registro TXT na zona DNS:"
    echo "Nome: default._domainkey.$DOMAIN"
    echo "Valor:"
    cat /etc/opendkim/keys/default.txt
    echo "=============================================================="
fi
echo ""
echo "🔄 O servidor será reiniciado em 15 segundos..."
sleep 15
reboot
