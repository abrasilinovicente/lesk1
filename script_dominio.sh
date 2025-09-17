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
# 9. CONFIGURAÇÃO CLOUDFLARE DNS (EXTRAÇÃO ULTRA LIMPA)
# ==============================================================================
if [ -n "$CLOUDFLARE_API" ] && [ -n "$CLOUDFLARE_EMAIL" ]; then
    echo "-> Configurando DNS no Cloudflare..."
    
    # Mostrar o arquivo original para debug
    echo "-> Conteúdo do arquivo DKIM:"
    cat /etc/opendkim/keys/default.txt
    echo "================================"
    
    # Extrair código DKIM (método ultra preciso)
    echo "-> Extraindo código DKIM..."
    
    # Método 1: Extrair APENAS o que está entre aspas duplas, ignorando comentários
    DKIM_CODE=$(sed -n '
        /p=/{
            :loop
            s/.*p="//
            s/"[^"]*$//
            s/".*//
            p
            n
            /^[[:space:]]*"/{
                s/^[[:space:]]*"//
                s/".*//
                p
                b loop
            }
        }
    ' /etc/opendkim/keys/default.txt | tr -d '\n' | sed 's/[^A-Za-z0-9+\/=]//g')
    
    # Se não funcionou, método mais simples
    if [ -z "$DKIM_CODE" ] || [ ${#DKIM_CODE} -lt 300 ]; then
        echo "-> Tentando método alternativo..."
        
        # Extrair linha por linha, apenas conteúdo entre aspas
        DKIM_CODE=""
        IN_DKIM=false
        
        while IFS= read -r line; do
            # Ignorar linhas de comentário
            if echo "$line" | grep -q "; -----"; then
                break
            fi
            
            if echo "$line" | grep -q 'p='; then
                IN_DKIM=true
                # Extrair apenas o que está após p=" e antes da próxima "
                temp=$(echo "$line" | sed 's/.*p="//; s/".*//')
                DKIM_CODE="$DKIM_CODE$temp"
            elif [ "$IN_DKIM" = true ] && echo "$line" | grep -q '^[[:space:]]*"'; then
                # Linha de continuação - extrair apenas entre aspas
                temp=$(echo "$line" | sed 's/^[[:space:]]*"//; s/".*//')
                DKIM_CODE="$DKIM_CODE$temp"
                
                # Se a linha termina com ") - fim do registro
                if echo "$line" | grep -q '")'; then
                    break
                fi
            fi
        done < /etc/opendkim/keys/default.txt
        
        # Limpar qualquer caractere que não seja Base64
        DKIM_CODE=$(echo "$DKIM_CODE" | sed 's/[^A-Za-z0-9+\/=]//g')
    fi
    
    echo "-> Código DKIM extraído:"
    echo "   Tamanho: ${#DKIM_CODE} caracteres"
    echo "   Início: ${DKIM_CODE:0:50}..."
    echo "   Final: ...${DKIM_CODE: -50}"
    
    # Validação final da chave
    if [ ${#DKIM_CODE} -lt 300 ]; then
        echo "❌ ERRO: Chave DKIM muito curta (${#DKIM_CODE} caracteres)"
        echo "Chave extraída: '$DKIM_CODE'"
        exit 1
    fi
    
    # Verificar se é Base64 válido
    if ! echo "$DKIM_CODE" | grep -q '^[A-Za-z0-9+/]*=*$'; then
        echo "❌ ERRO: Chave DKIM não parece ser Base64 válida"
        echo "Chave extraída: '$DKIM_CODE'"
        exit 1
    fi
    
    echo "✅ Chave DKIM válida extraída!"
    
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
        
        # Deletar registros DKIM existentes primeiro
        echo "-> Removendo registros DKIM antigos..."
        EXISTING_RECORDS=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=default._domainkey.$DOMAIN&type=TXT" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API" \
            -H "Content-Type: application/json")
        
        # Deletar cada registro existente
        echo "$EXISTING_RECORDS" | jq -r '.result[]?.id' 2>/dev/null | while read -r record_id; do
            if [ -n "$record_id" ] && [ "$record_id" != "null" ]; then
                echo "-> Deletando registro antigo: $record_id"
                curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$record_id" \
                    -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
                    -H "X-Auth-Key: $CLOUDFLARE_API" > /dev/null
            fi
        done
        
        # Aguardar um pouco para a propagação
        sleep 2
        
        # Criar novo registro DKIM limpo
        echo "-> Criando novo registro DKIM..."
        
        # Preparar conteúdo LIMPO (SEM caracteres extras)
        DKIM_CONTENT="v=DKIM1; h=sha256; k=rsa; p=$DKIM_CODE"
        
        echo "-> Registro a ser criado:"
        echo "   Nome: default._domainkey.$DOMAIN"
        echo "   Tipo: TXT"
        echo "   Tamanho: ${#DKIM_CONTENT} caracteres"
        echo "   Preview: ${DKIM_CONTENT:0:80}..."
        
        # Fazer a requisição
        RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"TXT\",\"name\":\"default._domainkey.$DOMAIN\",\"content\":\"$DKIM_CONTENT\",\"ttl\":300,\"proxied\":false}")
        
        echo "-> Resposta da API:"
        echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
        
        # Verificar se houve sucesso
        if echo "$RESPONSE" | grep -q '"success":true'; then
            echo "✅ Registro DKIM criado com sucesso!"
            RECORD_ID=$(echo "$RESPONSE" | jq -r '.result.id' 2>/dev/null)
            echo "✅ ID do registro: $RECORD_ID"
            echo "✅ Chave DKIM de ${#DKIM_CODE} caracteres configurada corretamente!"
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
