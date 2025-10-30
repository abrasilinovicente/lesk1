#!/bin/bash

# ============================================================
# SCRIPT FINAL - INSTALAÇÃO E CONFIGURAÇÃO SEM CLOUDFLARE
# ============================================================

# Verifica se recebeu 6 argumentos essenciais
if [ "$#" -ne 6 ]; then
    echo "ERRO: Número incorreto de argumentos. São necessários 6."
    echo "Uso: $0 <DOMAIN> <URL_APP_ZIP> <URL_ENVIO_ZIP> <URL_VAZIO> <URL_OPENDKIM_CONF> <URL_POSTFIX_CONF>"
    exit 1
fi

DOMAIN="$1"
URL_APP_ZIP="$2"
URL_ENVIO_ZIP="$3"
# Argumento vazio reservado
URL_OPENDKIM_CONF="$5"
URL_POSTFIX_CONF="$6"

# ============================================================
# ATUALIZAÇÃO E INSTALAÇÃO DE PACOTES
# ============================================================

echo "🔄 Atualizando repositórios e instalando pacotes essenciais..."
apt update && apt upgrade -y
apt install -y unzip curl wget sudo opendkim opendkim-tools postfix mailutils

# ============================================================
# CONFIGURAÇÃO OPENDKIM
# ============================================================

echo "🔧 Configurando OpenDKIM..."

# Cria pastas de chaves
mkdir -p /etc/opendkim/keys/$DOMAIN
cd /etc/opendkim/keys/$DOMAIN

# Gera chave DKIM
opendkim-genkey -s default -d "$DOMAIN"
chown opendkim:opendkim default.private
chmod 600 default.private

# Mostra instrução de DNS
echo ""
echo "⚠️ ATENÇÃO: Adicione o seguinte registro TXT no seu provedor de DNS:"
echo "Nome: default._domainkey.$DOMAIN"
echo "Valor:"
cat default.txt
echo ""

# Configura arquivos de configuração do OpenDKIM
cp "$URL_OPENDKIM_CONF" /etc/opendkim.conf
sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN|g" /etc/opendkim.conf

# ============================================================
# CONFIGURAÇÃO POSTFIX
# ============================================================

echo "✉️ Configurando Postfix..."
cp "$URL_POSTFIX_CONF" /etc/postfix/main.cf
sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN|g" /etc/postfix/main.cf

systemctl restart postfix
systemctl restart opendkim

# ============================================================
# DESCOMPACTAR APLICAÇÃO
# ============================================================

echo "📦 Baixando e descompactando aplicação..."
mkdir -p /var/www/$DOMAIN
wget -O /tmp/app.zip "$URL_APP_ZIP"
unzip /tmp/app.zip -d /var/www/$DOMAIN
chown -R www-data:www-data /var/www/$DOMAIN

wget -O /tmp/envio.zip "$URL_ENVIO_ZIP"
unzip /tmp/envio.zip -d /var/www/$DOMAIN/envio
chown -R www-data:www-data /var/www/$DOMAIN/envio

# ============================================================
# FINALIZAÇÃO
# ============================================================

echo ""
echo "✅ Instalação concluída!"
echo "Lembre-se: você deve adicionar o registro DKIM manualmente no DNS."
echo "Serviço Postfix e OpenDKIM estão ativos."

