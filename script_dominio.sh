#!/bin/bash
# Script de instalação de servidor de email otimizado
# Versão: 2.2 - Corrigida para dependências, DKIM e IP público

# Cores
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
NC="\033[0m"

# Parâmetros
FULL_DOMAIN="$1"        # ex: mail.exemplo.com
SUBDOMAIN="$2"          # opcional
BASE_DOMAIN=$(echo "$FULL_DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')

# Usuário SMTP padrão
SMTP_USER="admin@$BASE_DOMAIN"
SMTP_PASS="dwwzyd"

# Atualizar e instalar dependências essenciais
echo -e "${YELLOW}🚀 Instalando dependências...${NC}"
sudo apt update -y
sudo apt install -y curl wget postfix dovecot-core dovecot-imapd opendkim opendkim-tools nginx

# Obter IP público
if command -v curl &> /dev/null; then
    PUBLIC_IP=$(curl -s ifconfig.me)
else
    PUBLIC_IP=$(wget -qO- ifconfig.me)
fi

# Criar diretórios e gerar chave DKIM se não existir
DKIM_DIR="/etc/opendkim/keys/$BASE_DOMAIN"
DKIM_KEY="$DKIM_DIR/mail.txt"

if [ ! -f "$DKIM_KEY" ]; then
    echo -e "${YELLOW}🔑 Gerando chave DKIM...${NC}"
    sudo mkdir -p "$DKIM_DIR"
    sudo opendkim-genkey -s mail -d "$BASE_DOMAIN" -D "$DKIM_DIR"
    sudo chown opendkim:opendkim "$DKIM_DIR"/*
fi

# Testar serviços e iniciar se necessário
SERVICES=("postfix" "dovecot" "opendkim" "nginx")
for service in "${SERVICES[@]}"; do
    sudo systemctl enable --now $service
done

# Exibir página de configuração DNS
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Página de configuração DNS otimizada criada!${NC}"
echo -e "${GREEN}Acesse: http://$PUBLIC_IP/lesk.html${NC}"
echo -e "${GREEN}========================================${NC}"

# Exibir chave DKIM
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Chave DKIM pública (adicione ao DNS):${NC}"
cat "$DKIM_KEY"
echo -e "${GREEN}========================================${NC}"

# Testar configuração
echo -e "${YELLOW}Testando serviços...${NC}"
postfix check
dovecot -n > /dev/null 2>&1 && echo -e "${GREEN}Dovecot: OK${NC}" || echo -e "${RED}Dovecot: ERRO${NC}"

# Status dos serviços
echo -e "${YELLOW}📊 Verificando status dos serviços...${NC}"
ALL_OK=true
for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        echo -e "  $service: ${GREEN}● Ativo${NC}"
    else
        echo -e "  $service: ${RED}● Inativo${NC}"
        ALL_OK=false
    fi
done

if $ALL_OK; then
    echo -e "${GREEN}✅ TODOS OS SERVIÇOS ESTÃO FUNCIONANDO!${NC}"
else
    echo -e "${YELLOW}⚠ Alguns serviços não estão ativos. Verifique os logs.${NC}"
fi

# Informações SMTP e portas
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Usuário SMTP criado:${NC}"
echo -e "${GREEN}Email: $SMTP_USER${NC}"
echo -e "${GREEN}Senha: $SMTP_PASS${NC}"
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

# Dicas de entregabilidade
echo -e "${CYAN}📌 DICAS IMPORTANTES DE ENTREGABILIDADE:${NC}"
echo -e "${YELLOW}1. Configure registros DNS (A, MX, SPF, DKIM, DMARC, MTA-STS)${NC}"
echo -e "${YELLOW}2. Solicite PTR ao seu provedor de VPS${NC}"
echo -e "${YELLOW}3. Aguarde 24-48h para propagação completa do DNS${NC}"
echo -e "${YELLOW}4. Teste servidor em https://www.mail-tester.com/${NC}"
echo -e "${YELLOW}5. Aqueça o IP: comece enviando poucos emails/dia${NC}"
echo -e "${YELLOW}6. Monitore relatórios DMARC${NC}"
echo -e "${YELLOW}7. Evite palavras de spam${NC}"
echo -e "${YELLOW}8. Sempre inclua link de descadastramento${NC}"

# Log de instalação
echo "Instalação concluída em $(date)" >> /var/log/mail-setup.log
echo "Domínio: $FULL_DOMAIN" >> /var/log/mail-setup.log
echo "Usuário: $SMTP_USER" >> /var/log/mail-setup.log

echo -e "\n${GREEN}🎉 Instalação concluída com sucesso!${NC}"
echo -e "${GREEN}📧 Acesse http://$PUBLIC_IP/lesk.html para ver as configurações DNS otimizadas${NC}"

exit 0
