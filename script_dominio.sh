#!/bin/bash
# Script de configuração completa de servidor de e-mail
# Suporta Ubuntu 20.04/22.04

# ======== CORES ========
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
NC="\033[0m"

# ======== FUNÇÃO PARA GERAR SENHA ========
generate_password() {
    tr -dc 'A-Za-z0-9!@#$%&*()_+-=' </dev/urandom | head -c 16
}

# ======== VALIDAR DOMÍNIO ========
if [ -z "$1" ]; then
    echo -e "${RED}Erro: Informe o domínio como parâmetro.${NC}"
    echo "Ex: bash $0 seu-dominio.com"
    exit 1
fi

DOMAIN="$1"
SMTP_USER="admin@$DOMAIN"
SMTP_PASS=$(generate_password)
DKIM_SELECTOR="mail"

# ======== ATUALIZAR SISTEMA E INSTALAR PACOTES ========
echo -e "${CYAN}Atualizando sistema e instalando pacotes...${NC}"
apt update && apt upgrade -y
apt install -y postfix dovecot-core dovecot-imapd dovecot-pop3d opendkim opendkim-tools wget curl

# ======== CONFIGURAR DKIM ========
echo -e "${CYAN}Configurando OpenDKIM...${NC}"
mkdir -p /etc/opendkim/keys/$DOMAIN
opendkim-genkey -D /etc/opendkim/keys/$DOMAIN -d $DOMAIN -s $DKIM_SELECTOR
chown opendkim:opendkim /etc/opendkim/keys/$DOMAIN/*
mv /etc/opendkim/keys/$DOMAIN/$DKIM_SELECTOR.private /etc/opendkim/keys/$DOMAIN/mail.key

# Criar TXT DKIM pronto para copiar
DKIM_TXT=$(cat /etc/opendkim/keys/$DOMAIN/$DKIM_SELECTOR.txt | awk '{$1=""; print $0}')

# ======== CONFIGURAR POSTFIX ========
echo -e "${CYAN}Configurando Postfix...${NC}"
postconf -e "myhostname = mail.$DOMAIN"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = /etc/mailname"
postconf -e "smtpd_banner = \$myhostname ESMTP"
postconf -e "mynetworks = 127.0.0.0/8"
postconf -e "home_mailbox = Maildir/"
postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem"
postconf -e "smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key"
postconf -e "smtpd_use_tls = yes"
postconf -e "smtpd_tls_auth_only = yes"

# ======== CONFIGURAR USUÁRIO SMTP ========
echo -e "${CYAN}Criando usuário SMTP...${NC}"
useradd -m -s /sbin/nologin admin
echo "admin:$SMTP_PASS" | chpasswd

# ======== GERAR REGISTROS DNS ========
SPF="v=spf1 a mx ~all"
DMARC="v=DMARC1; p=none; rua=mailto:dmarc-reports@$DOMAIN"
MX="mail.$DOMAIN"

# ======== EXIBIR INFORMAÇÕES FINAIS ========
echo -e "\n${GREEN}✅ Instalação concluída!${NC}"
echo -e "${GREEN}Usuário SMTP:${NC} $SMTP_USER"
echo -e "${GREEN}Senha SMTP:${NC} $SMTP_PASS"

echo -e "\n${YELLOW}📌 Registros DNS para configurar no seu domínio:${NC}"
echo -e "${YELLOW}SPF (TXT):${NC} $SPF"
echo -e "${YELLOW}DKIM (TXT) - selector: $DKIM_SELECTOR:${NC} $DKIM_TXT"
echo -e "${YELLOW}DMARC (TXT):${NC} $DMARC"
echo -e "${YELLOW}MX:${NC} $MX"

# ======== TESTAR SERVIÇOS ========
echo -e "\n${CYAN}Testando serviços...${NC}"
for service in postfix dovecot opendkim; do
    systemctl is-active --quiet $service && echo -e "  $service: ${GREEN}Ativo${NC}" || echo -e "  $service: ${RED}Inativo${NC}"
done

# ======== TESTAR PORTAS ========
PORTS=(25 465 587 143 993 110 995)
echo -e "\n${CYAN}Testando portas de serviço...${NC}"
for port in "${PORTS[@]}"; do
    nc -zv 127.0.0.1 $port &>/dev/null && echo -e "  Porta $port: ${GREEN}Aberta${NC}" || echo -e "  Porta $port: ${RED}Fechada${NC}"
done

# ======== GERAR RELATÓRIO HTML SIMPLES ========
REPORT="/var/log/mail-setup-report.html"
echo "<html><body><h2>Status do Servidor de E-mail - $DOMAIN</h2><ul>" > $REPORT
for service in postfix dovecot opendkim; do
    STATUS=$(systemctl is-active $service)
    echo "<li>$service: $STATUS</li>" >> $REPORT
done
echo "</ul><h3>Portas:</h3><ul>" >> $REPORT
for port in "${PORTS[@]}"; do
    nc -zv 127.0.0.1 $port &>/dev/null && STATUS="Aberta" || STATUS="Fechada"
    echo "<li>Porta $port: $STATUS</li>" >> $REPORT
done
echo "</ul></body></html>" >> $REPORT

echo -e "\n📄 Relatório HTML gerado em $REPORT"

# ======== LOG ========
echo "Instalação completa em $(date)" >> /var/log/mail-setup.log
echo "Domínio: $DOMAIN" >> /var/log/mail-setup.log
echo "Usuário SMTP: $SMTP_USER" >> /var/log/mail-setup.log
echo "Senha SMTP: $SMTP_PASS" >> /var/log/mail-setup.log

echo -e "\n${CYAN}💡 Copie os registros DNS acima e configure no seu provedor de domínio.${NC}"

exit 0
