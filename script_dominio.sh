#!/bin/bash

# =====================================================
# CORREÇÃO RÁPIDA - Criar página lesk.html
# Execute este script no seu servidor para corrigir
# =====================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  CORREÇÃO - Criar lesk.html${NC}"
echo -e "${CYAN}========================================${NC}\n"

# Detectar configurações
PUBLIC_IP=$(curl -s ifconfig.me)
BASE_DOMAIN=$(cat /etc/mailname 2>/dev/null)
FULL_DOMAIN=$(hostname)
SUBDOMAIN=$(echo "$FULL_DOMAIN" | cut -d'.' -f1)

echo -e "${YELLOW}IP: $PUBLIC_IP${NC}"
echo -e "${YELLOW}Domínio: $BASE_DOMAIN${NC}"
echo -e "${YELLOW}Hostname: $FULL_DOMAIN${NC}"
echo -e "${YELLOW}Subdomínio: $SUBDOMAIN${NC}\n"

# Buscar chave DKIM
DKIM_FILE="/etc/opendkim/keys/$BASE_DOMAIN/$SUBDOMAIN.txt"
if [ ! -f "$DKIM_FILE" ]; then
    DKIM_FILE=$(find /etc/opendkim/keys -name "*.txt" 2>/dev/null | head -1)
fi

if [ -f "$DKIM_FILE" ]; then
    DKIM_KEY=$(cat "$DKIM_FILE" | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ";' | sed 's/)//')
    echo -e "${GREEN}✓ Chave DKIM encontrada${NC}"
else
    DKIM_KEY="CHAVE_NAO_ENCONTRADA"
    echo -e "${RED}✗ Chave DKIM não encontrada${NC}"
fi

# Criar HTML
echo -e "${YELLOW}Criando lesk.html...${NC}"

cat > /var/www/html/lesk.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurações DNS - DOMAIN_PH</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .dns-type {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .dns-label {
            font-weight: 600;
            color: #555;
            margin-top: 10px;
        }
        .dns-value {
            background: #f5f5f5;
            padding: 12px 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            word-break: break-all;
            margin: 5px 0;
            cursor: pointer;
        }
        .dns-value:hover {
            background: #e8e8e8;
        }
        .info-box {
            background: #f0f7ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-top: 15px;
            border-radius: 5px;
        }
        .status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            margin-left: 10px;
            background: #ff4444;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚙️ Configurações DNS</h1>
            <p>Domínio: FULL_DOMAIN_PH</p>
            <p>Base: DOMAIN_PH</p>
        </div>

        <!-- Registro A -->
        <div class="card">
            <span class="dns-type">TIPO A</span>
            <span class="status-badge">Obrigatório</span>
            <div class="dns-label">Nome:</div>
            <div class="dns-value" onclick="copyText(this)">SUBDOMAIN_PH</div>
            <div class="dns-label">Conteúdo (IP):</div>
            <div class="dns-value" onclick="copyText(this)">IP_PH</div>
            <div class="dns-label">TTL:</div>
            <div class="dns-value" onclick="copyText(this)">3600</div>
            <div class="info-box">
                <strong>ℹ️ Sobre:</strong> Aponta o subdomínio para o IP do servidor.
            </div>
        </div>

        <!-- Registro MX -->
        <div class="card">
            <span class="dns-type">TIPO MX</span>
            <span class="status-badge">Obrigatório</span>
            <div class="dns-label">Nome:</div>
            <div class="dns-value" onclick="copyText(this)">@</div>
            <div class="dns-label">Servidor de Email:</div>
            <div class="dns-value" onclick="copyText(this)">FULL_DOMAIN_PH</div>
            <div class="dns-label">Prioridade:</div>
            <div class="dns-value" onclick="copyText(this)">10</div>
            <div class="dns-label">TTL:</div>
            <div class="dns-value" onclick="copyText(this)">3600</div>
            <div class="info-box">
                <strong>ℹ️ Sobre:</strong> Define qual servidor recebe emails do domínio.
            </div>
        </div>

        <!-- Registro SPF -->
        <div class="card">
            <span class="dns-type">TIPO TXT (SPF)</span>
            <span class="status-badge">Obrigatório</span>
            <div class="dns-label">Nome:</div>
            <div class="dns-value" onclick="copyText(this)">@</div>
            <div class="dns-label">Conteúdo:</div>
            <div class="dns-value" onclick="copyText(this)">v=spf1 ip4:IP_PH mx a:FULL_DOMAIN_PH -all</div>
            <div class="dns-label">TTL:</div>
            <div class="dns-value" onclick="copyText(this)">3600</div>
            <div class="info-box">
                <strong>ℹ️ Sobre:</strong> Autoriza quais servidores podem enviar emails pelo domínio. 
                O "-all" é restritivo e melhora a reputação.
            </div>
        </div>

        <!-- Registro DKIM -->
        <div class="card">
            <span class="dns-type">TIPO TXT (DKIM)</span>
            <span class="status-badge">Obrigatório</span>
            <div class="dns-label">Nome:</div>
            <div class="dns-value" onclick="copyText(this)">SUBDOMAIN_PH._domainkey</div>
            <div class="dns-label">Conteúdo:</div>
            <div class="dns-value" onclick="copyText(this)">v=DKIM1; k=rsa; t=s; s=email; p=DKIM_KEY_PH</div>
            <div class="dns-label">TTL:</div>
            <div class="dns-value" onclick="copyText(this)">3600</div>
            <div class="info-box">
                <strong>ℹ️ Sobre:</strong> Assinatura digital dos emails. 
                Modo "strict" (t=s) para máxima validação.
            </div>
        </div>

        <!-- Registro DMARC -->
        <div class="card">
            <span class="dns-type">TIPO TXT (DMARC)</span>
            <span class="status-badge">Obrigatório</span>
            <div class="dns-label">Nome:</div>
            <div class="dns-value" onclick="copyText(this)">_dmarc</div>
            <div class="dns-label">Conteúdo:</div>
            <div class="dns-value" onclick="copyText(this)">v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc-reports@DOMAIN_PH; ruf=mailto:dmarc-failures@DOMAIN_PH; fo=1; adkim=s; aspf=s; pct=100; ri=86400</div>
            <div class="dns-label">TTL:</div>
            <div class="dns-value" onclick="copyText(this)">3600</div>
            <div class="info-box">
                <strong>ℹ️ Sobre:</strong> Política de autenticação com alinhamento estrito. 
                Você receberá relatórios diários em dmarc-reports@DOMAIN_PH
            </div>
        </div>

        <!-- MTA-STS -->
        <div class="card">
            <span class="dns-type">TIPO TXT (MTA-STS)</span>
            <span class="status-badge">Recomendado</span>
            <div class="dns-label">Nome:</div>
            <div class="dns-value" onclick="copyText(this)">_mta-sts</div>
            <div class="dns-label">Conteúdo:</div>
            <div class="dns-value" onclick="copyText(this)">v=STSv1; id=TIMESTAMP_PH</div>
            <div class="dns-label">TTL:</div>
            <div class="dns-value" onclick="copyText(this)">3600</div>
            <div class="info-box">
                <strong>ℹ️ Sobre:</strong> Força uso de TLS criptografado.
            </div>
        </div>

        <!-- Informações do Servidor -->
        <div class="card" style="background: #e8f5e9;">
            <h2>🖥️ Informações do Servidor</h2>
            <div class="dns-label">IP do Servidor:</div>
            <div class="dns-value">IP_PH</div>
            <div class="dns-label">Hostname:</div>
            <div class="dns-value">FULL_DOMAIN_PH</div>
            <div class="dns-label">Usuário SMTP:</div>
            <div class="dns-value">admin@DOMAIN_PH</div>
            <div class="dns-label">Senha SMTP:</div>
            <div class="dns-value">dwwzyd</div>
            <div class="dns-label">Portas:</div>
            <div class="dns-value">SMTP: 25, 587, 465 | IMAP: 143, 993 | POP3: 110, 995</div>
        </div>

        <!-- Checklist -->
        <div class="card" style="background: #fff3e0;">
            <h2>✅ Checklist de Configuração</h2>
            <ol style="margin-left: 20px; line-height: 2;">
                <li>Configure Registro A</li>
                <li>Configure Registro MX</li>
                <li>Configure SPF, DKIM e DMARC</li>
                <li>Configure MTA-STS</li>
                <li>Aguarde 24-48h para propagação DNS</li>
                <li>Teste em https://www.mail-tester.com/</li>
                <li>Solicite PTR ao provedor de VPS</li>
            </ol>
        </div>
    </div>

    <script>
        function copyText(element) {
            const text = element.textContent.trim();
            navigator.clipboard.writeText(text).then(() => {
                const original = element.style.background;
                element.style.background = '#4caf50';
                element.style.color = 'white';
                element.innerHTML = '✓ Copiado: ' + text;
                setTimeout(() => {
                    element.style.background = original;
                    element.style.color = 'black';
                    element.innerHTML = text;
                }, 2000);
            });
        }
    </script>
</body>
</html>
EOF

# Substituir placeholders
sed -i "s/DOMAIN_PH/$BASE_DOMAIN/g" /var/www/html/lesk.html
sed -i "s/FULL_DOMAIN_PH/$FULL_DOMAIN/g" /var/www/html/lesk.html
sed -i "s/SUBDOMAIN_PH/$SUBDOMAIN/g" /var/www/html/lesk.html
sed -i "s|IP_PH|$PUBLIC_IP|g" /var/www/html/lesk.html
sed -i "s/DKIM_KEY_PH/$DKIM_KEY/g" /var/www/html/lesk.html
sed -i "s/TIMESTAMP_PH/$(date +%Y%m%d%H%M%S)/g" /var/www/html/lesk.html

# Permissões
chmod 644 /var/www/html/lesk.html
chown www-data:www-data /var/www/html/lesk.html 2>/dev/null || chown nginx:nginx /var/www/html/lesk.html 2>/dev/null

# Reiniciar Nginx
systemctl reload nginx 2>/dev/null || systemctl restart nginx

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Página criada com sucesso!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Acesse: http://$PUBLIC_IP/lesk.html${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Verificar
if [ -f "/var/www/html/lesk.html" ]; then
    SIZE=$(stat -c%s "/var/www/html/lesk.html" 2>/dev/null || stat -f%z "/var/www/html/lesk.html")
    echo -e "${GREEN}Tamanho do arquivo: $SIZE bytes${NC}"
    echo -e "${GREEN}Status: OK ✓${NC}\n"
else
    echo -e "${RED}ERRO: Arquivo não foi criado!${NC}\n"
fi
