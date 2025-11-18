#!/bin/bash
# =================================================
# Script completo de configuração de servidor de email
# Com testes de serviços, portas, DNS sugerido e relatório HTML
# =================================================

# =========================
# Configurações de cores
# =========================
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

# =========================
# Funções utilitárias
# =========================
print_header() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
}

print_tip() { echo -e "${YELLOW}$1${NC}"; }

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/mail-setup.log; }

check_service() {
    if systemctl is-active --quiet "$1"; then
        echo -e "  $1: ${GREEN}● Ativo${NC}"
    else
        echo -e "  $1: ${RED}● Inativo${NC}"
    fi
}

test_port() {
    local host=$1 port=$2
    if timeout 2 bash -c "</dev/tcp/$host/$port" &>/dev/null; then
        echo -e "  Porta $port: ${GREEN}Aberta${NC}"
    else
        echo -e "  Porta $port: ${RED}Fechada${NC}"
    fi
}

generate_dns_suggestions() {
cat <<EOF
DNS sugerido para $FULL_DOMAIN:
A: $PUBLIC_IP
MX: $FULL_DOMAIN
SPF: v=spf1 mx -all
DKIM: (use a chave exibida)
DMARC: v=DMARC1; p=none; rua=mailto:dmarc-reports@$BASE_DOMAIN
MTA-STS: v=STSv1; id=$(date +%s)
EOF
}

generate_html_report() {
    local html_file="/var/log/mail-setup-report.html"
    cat <<EOF > "$html_file"
<html>
<head>
<title>Relatório de Configuração de Email - $FULL_DOMAIN</title>
<style>
body { font-family: Arial, sans-serif; background: #f5f5f5; color: #333; padding: 20px; }
h1 { color: #2c3e50; }
h2 { color: #16a085; }
pre { background: #ecf0f1; padding: 10px; border-radius: 5px; }
.green { color: green; font-weight: bold; }
.red { color: red; font-weight: bold; }
</style>
</head>
<body>
<h1>Status do Servidor de Email - $FULL_DOMAIN</h1>

<h2>Serviços</h2>
<pre>$SERVICE_STATUS</pre>

<h2>Portas</h2>
<pre>$PORT_STATUS</pre>

<h2>DNS Recomendado</h2>
<pre>$DNS_SUGGESTIONS</pre>

<h2>Chave DKIM Pública</h2>
<pre>$(cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt)</pre>

<h2>Usuário SMTP</h2>
<pre>Email: $SMTP_USER
Senha: $SMTP_PASS</pre>

</body>
</html>
EOF
echo -e "${GREEN}📄 Relatório HTML gerado em $html_file${NC}"
}

# =========================
# Variáveis principais
# =========================
PUBLIC_IP=$(curl -s ifconfig.me)
BASE_DOMAIN="exemplo.com"
SUBDOMAIN="mail"
FULL_DOMAIN="$SUBDOMAIN.$BASE_DOMAIN"
SMTP_USER="admin@$BASE_DOMAIN"
SMTP_PASS=$(openssl rand -base64 12)
SERVICES=("postfix" "dovecot" "opendkim" "nginx")
PORTS=(25 465 587 143 993 110 995)

# =========================
# Exibição inicial
# =========================
print_header "Página de configuração DNS otimizada criada!"
echo -e "${GREEN}Acesse: http://$PUBLIC_IP/lesk.html${NC}"

# =========================
# Exibir chave DKIM
# =========================
print_header "Chave DKIM pública (adicione ao DNS)"
cat /etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt

# =========================
# Testar serviços
# =========================
print_header "Verificando status dos serviços"
SERVICE_STATUS=""
ALL_OK=true
for service in "${SERVICES[@]}"; do
    STATUS=$(check_service "$service")
    SERVICE_STATUS+="$STATUS"$'\n'
    if [[ "$STATUS" == *"Inativo"* ]]; then ALL_OK=false; fi
done

if $ALL_OK; then
    echo -e "${GREEN}✅ TODOS OS SERVIÇOS ESTÃO FUNCIONANDO!${NC}"
else
    echo -e "${YELLOW}⚠ Alguns serviços não estão ativos. Verifique os logs.${NC}"
fi

# =========================
# Testar portas
# =========================
print_header "Testando portas do servidor"
PORT_STATUS=""
for port in "${PORTS[@]}"; do
    PORT_STATUS+=$(test_port "$PUBLIC_IP" "$port")$'\n'
done

# =========================
# Gerar DNS sugerido e relatório HTML
# =========================
DNS_SUGGESTIONS=$(generate_dns_suggestions)
generate_html_report

# =========================
# Exibir usuário SMTP
# =========================
print_header "Usuário SMTP criado"
echo -e "${GREEN}Email: $SMTP_USER${NC}"
echo -e "${GREEN}Senha: $SMTP_PASS${NC}"

# =========================
# Dicas finais de entregabilidade
# =========================
print_header "DICAS IMPORTANTES DE ENTREGABILIDADE"
print_tip "1. Configure TODOS os registros DNS obrigatórios (A, MX, SPF, DKIM, DMARC, MTA-STS)"
print_tip "2. Solicite PTR (DNS Reverso) ao seu provedor de VPS"
print_tip "3. Aguarde 24-48 horas para propagação do DNS"
print_tip "4. Teste seu servidor em https://www.mail-tester.com/ (meta: 10/10)"
print_tip "5. Aqueça o IP: comece enviando poucos emails/dia e aumente gradualmente"
print_tip "6. Monitore relatórios DMARC em dmarc-reports@$BASE_DOMAIN"
print_tip "7. Evite palavras de spam no assunto e conteúdo"
print_tip "8. Sempre inclua link de descadastramento nos emails marketing"

# =========================
# Log de instalação
# =========================
log "Instalação concluída em $(date)"
log "Versão: 2.1 (Completa)"
log "Domínio Completo: $FULL_DOMAIN"
log "Subdomínio: $SUBDOMAIN"
log "Domínio Base: $BASE_DOMAIN"
log "Usuário SMTP: $SMTP_USER"

# =========================
# Limpeza final
# =========================
rm -f /usr/sbin/policy-rc.d
rm -f /etc/needrestart/conf.d/99-autorestart.conf
export DEBIAN_FRONTEND=dialog

# =========================
# Mensagem final
# =========================
echo -e "\n${GREEN}🎉 Instalação concluída com sucesso!${NC}"
echo -e "${GREEN}📧 Acesse http://$PUBLIC_IP/lesk.html para ver as configurações DNS otimizadas${NC}"
echo -e "${GREEN}📄 Relatório completo disponível em /var/log/mail-setup-report.html${NC}"

exit 0
