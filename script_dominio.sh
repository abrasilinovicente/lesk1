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
# 9. CONFIGURAÇÃO CLOUDFLARE DNS (EXTRAÇÃO DKIM LIMPA)
# ==============================================================================
if [ -n "$CLOUDFLARE_API" ] && [ -n "$CLOUDFLARE_EMAIL" ]; then
    echo "-> Configurando DNS no Cloudflare..."
    
    # Extrair código DKIM (método limpo e preciso)
    echo "-> Extraindo código DKIM completo..."
    
    # Método mais preciso: extrair apenas o conteúdo entre aspas após p=
    DKIM_CODE=$(awk '
    BEGIN { dkim = "" }
    /p=/ {
        # Encontrou linha com p=, extrair tudo após p= até a primeira aspa de fechamento
        match($0, /p="([^"]*)"/, arr)
        if (arr[1]) dkim = dkim arr[1]
        # Se não encontrou aspas na mesma linha, continuar nas próximas
        if (!arr[1]) {
            gsub(/.*p="/, "")
            gsub(/".*/, "")
            dkim = dkim $0
        }
    }
    /^[[:space:]]*"[^"]*"/ && dkim != "" {
        # Linhas de continuação com aspas
        gsub(/^[[:space:]]*"/, "")
        gsub(/".*/, "")
        dkim = dkim $0
    }
    END { 
        # Limpar qualquer caractere inválido
        gsub(/[^A-Za-z0-9+\/=]/, "", dkim)
        print dkim 
    }
    ' /etc/opendkim/keys/default.txt)
    
    # Se o método acima não funcionou, usar método manual mais limpo
    if [ -z "$DKIM_CODE" ] || [ ${#DKIM_CODE} -lt 300 ]; then
        echo "-> Usando método manual limpo..."
        
        # Extrair apenas o que está entre aspas, linha por linha
        DKIM_CODE=""
        while IFS= read -r line; do
            if echo "$line" | grep -q 'p='; then
                # Primeira linha com p= - extrair tudo entre aspas
                temp=$(echo "$line" | sed 's/.*p="//; s/".*//')
                DKIM_CODE="$DKIM_CODE$temp"
            elif echo "$line" | grep -q '^[[:space:]]*".*"'; then
                # Linhas de continuação - extrair apenas o que está entre aspas
                temp=$(echo "$line" | sed 's/^[[:space:]]*"//; s/".*//')
                DKIM_CODE="$DKIM_CODE$temp"
            fi
        done < /etc/opendkim/keys/default.txt
        
        # Limpar caracteres inválidos (manter apenas Base64 válidos)
        DKIM_CODE=$(echo "$DKIM_CODE" | tr -d ' \t\n\r' | sed 's/[^A-Za-z0-9+\/=]//g')
    fi
    
    echo "-> Código DKIM extraído (${#DKIM_CODE} caracteres)"
    echo "-> Início: ${DKIM_CODE:0:50}..."
    echo "-> Final: ...${DKIM_CODE: -50}"
    
    # Validar se a chave parece ser Base64 válida
    if echo "$DKIM_CODE" | grep -q '^[A-Za-z0-9+/]*=*$' && [ ${#DKIM_CODE} -gt 300 ]; then
        echo "✅ Chave DKIM parece válida (Base64, ${#DKIM_CODE} caracteres)"
    else
        echo "⚠️ AVISO: Chave DKIM pode estar inválida"
        echo "Conteúdo extraído: $DKIM_CODE"
        echo ""
        echo "Arquivo original:"
        cat /etc/opendkim/keys/default.txt
    fi
    
    # Obter Zone ID
    echo "-> Obtendo Zone ID do Cloudflare para $MAIN_DOMAIN..."
    ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$MAIN_DOMAIN&status=active" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API" \
        -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
    
    if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" = "null" ]; then
        echo "⚠️ AVISO: Não foi possível obter o Zone ID para $MAIN_DOMAIN"
        echo ""
        echo "=== CONFIGURAÇÃO MANUAL NECESSÁRIA ==="
        echo "Nome: default._domainkey.$DOMAIN"
        echo "Tipo: TXT"
        echo "Valor: v=DKIM1; h=sha256; k=rsa; p=$DKIM_CODE"
        echo "======================================"
    else
        echo "✅ Zone ID obtido: $ZONE_ID"
        
        # Primeiro, tentar deletar registro existente (se houver)
        echo "-> Verificando registros DKIM existentes..."
        EXISTING_RECORDS=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=default._domainkey.$DOMAIN&type=TXT" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API" \
            -H "Content-Type: application/json")
        
        # Deletar registros existentes
        echo "$EXISTING_RECORDS" | jq -r '.result[].id' | while read -r record_id; do
            if [ -n "$record_id" ] && [ "$record_id" != "null" ]; then
                echo "-> Deletando registro DKIM existente: $record_id"
                curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$record_id" \
                    -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
                    -H "X-Auth-Key: $CLOUDFLARE_API" > /dev/null
            fi
        done
        
        # Cadastrar novo registro DKIM (limpo)
        echo "-> Cadastrando novo registro DKIM..."
        
        # Preparar conteúdo do registro DKIM (SEM caracteres extras)
        DKIM_CONTENT="v=DKIM1; h=sha256; k=rsa; p=$DKIM_CODE"
        
        echo "-> Criando registro TXT:"
        echo "   Nome: default._domainkey.$DOMAIN"
        echo "   Tamanho: ${#DKIM_CONTENT} caracteres"
        echo "   Conteúdo: ${DKIM_CONTENT:0:100}..."
        
        # Fazer a requisição
        RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"TXT\",\"name\":\"default._domainkey.$DOMAIN\",\"content\":\"$DKIM_CONTENT\",\"ttl\":300,\"proxied\":false}")
        
        # Verificar se houve sucesso
        if echo "$RESPONSE" | grep -q '"success":true'; then
            echo "✅ Registro DKIM criado com sucesso no Cloudflare!"
            echo "✅ Chave DKIM limpa de ${#DKIM_CODE} caracteres configurada!"
            
            # Mostrar o registro criado
            RECORD_ID=$(echo "$RESPONSE" | jq -r '.result.id')
            echo "✅ ID do registro: $RECORD_ID"
        else
            echo "❌ Erro ao criar registro DKIM:"
            echo "$RESPONSE"
        fi
    fi
    
    echo "✅ Configuração DNS finalizada!"
else
    echo "⚠️ Credenciais do Cloudflare não fornecidas."
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
