#!/bin/bash
# =====================================================
# Script Completo de Configuração de Servidor de Email
# =====================================================

# Cores
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
CYAN="\e[36m"
NC="\e[0m"

# Verifica se domínio foi informado
if [ -z "$1" ]; then
    echo -e "${RED}Erro: Informe o domínio!${NC}"
    echo -e "Exemplo: bash $0 example.com"
    exit 1
fi

DOMAIN="$1"
SMTP_USER="admin@$DOMAIN"
SMTP_PASS=$(openssl rand -base64 12)
DKIM_DIR="/etc/opendkim/keys/$DOMAIN"
PUBLIC_IP=$(curl -s https://ipinfo.io/ip || echo "SEU_IP_AQUI")

echo -e "${CYAN}🔹 Atualizando pacotes...${NC}"
apt update && apt upgrade -y

echo -e "${CYAN}🔹 Instalando dependências...${NC}"
apt install -y postfix dovecot-core dovecot-imapd dovecot-pop3d opendkim opendkim-tools openssl pwgen

# =====================================================
# Configuração OpenDKIM
# =====================================================
mkdir -p "$DKIM_DIR"
chmod 700 "$DKIM_DIR"

echo -e "${CYAN}🔹 Gerando chaves DKIM...${NC}"
openssl genrsa -out "$DKIM_DIR/mail.private" 2048
openssl rsa -in "$DKIM_DIR/mail.private" -pubout -out "$DKIM_DIR/mail.txt"

chown -R opendkim:opendkim "$DKIM_DIR"

# Configurar OpenDKIM
cat > /etc/opendkim.conf <<EOL
AutoRestart             Yes
AutoRestartRate         10/1h
Canonicalization        relaxed/simple
Domain                  $DOMAIN
KeyFile                 $DKIM_DIR/mail.private
Selector                mail
Socket                  inet:12301@localhost
Syslog                  yes
UMask                   002
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
UserID                  opendkim:opendkim
EOL

# Configura Postfix para usar OpenDKIM
echo "milter_default_action = accept" >> /etc/postfix/main.cf
echo "milter_protocol = 6" >> /etc/postfix/main.cf
echo "smtpd_milters = inet:localhost:12301" >> /etc/postfix/main.cf
echo "non_smtpd_milters = inet:localhost:12301" >> /etc/postfix/main.cf

systemctl enable opendkim
systemctl restart opendkim

# =====================================================
# Configuração Postfix básica
# =====================================================
echo -e "${CYAN}🔹 Configurando Postfix...${NC}"
debconf-set-selections <<< "postfix postfix/mailname string $DOMAIN"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
systemctl enable postfix
systemctl restart postfix

# =====================================================
# Configuração Dovecot básica
# =====================================================
echo -e "${CYAN}🔹 Configurando Dovecot...${NC}"
cat > /etc/dovecot/dovecot.conf <<EOL
disable_plaintext_auth = no
mail_location = maildir:~/Maildir
userdb {
  driver = passwd
}
passdb {
  driver = pam
}
protocols = imap pop3 lmtp
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOL

systemctl enable dovecot
systemctl restart dovecot

# =====================================================
# Criar usuário SMTP
# =====================================================
useradd -m -s /sbin/nologin admin
echo "admin:$SMTP_PASS" | chpasswd

# =====================================================
# Exibir informações
# =====================================================
echo -e "\n${GREEN}✅ Configuração concluída!${NC}"
echo -e "${GREEN}Usuário SMTP: ${NC}$SMTP_USER"
echo -e "${GREEN}Senha SMTP: ${NC}$SMTP_PASS"

# DNS recomendados
DKIM_PUB_KEY=$(openssl rsa -in $DKIM_DIR/mail.private -pubout -outform PEM | tail -n +2 | head -n -1 | tr -d '\n')
echo -e "\n${CYAN}📌 Configurações DNS a serem adicionadas no provedor:${NC}"
echo -e "${YELLOW}MX:${NC} Nome: @ | Tipo: MX | Prioridade: 10 | Valor: mail.$DOMAIN"
echo -e "${YELLOW}SPF:${NC} Nome: @ | Tipo: TXT | Valor: \"v=spf1 mx ~all\""
echo -e "${YELLOW}DKIM:${NC} Nome: mail._domainkey | Tipo: TXT | Valor: \"v=DKIM1; k=rsa; p=$DKIM_PUB_KEY\""
echo -e "${YELLOW}DMARC:${NC} Nome: _dmarc | Tipo: TXT | Valor: \"v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN\""

# =====================================================
# Status dos serviços
# =====================================================
echo -e "\n${CYAN}🔹 Verificando status dos serviços...${NC}"
SERVICES=("postfix" "dovecot" "opendkim")
for s in "${SERVICES[@]}"; do
    systemctl is-active --quiet $s && echo -e "  $s: ${GREEN}Ativo${NC}" || echo -e "  $s: ${RED}Inativo${NC}"
done

echo -e "\n${GREEN}🎉 Tudo pronto! Acesse seu servidor via SMTP/IMAP/POP3 com as credenciais acima.${NC}"
