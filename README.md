📊 O QUE O SISTEMA FAZ
1. Instalação automática:

Postfix (SMTP)
Dovecot (IMAP/POP3/SASL)
OpenDKIM (assinatura digital)
Nginx (para servir página HTML)

2. Configurações criadas:

main.cf do Postfix (automaticamente)
master.cf com todas as portas
Dovecot com autenticação SASL
Virtual mailboxes
Certificados SSL (snake oil ou Let's Encrypt)

3. Usuário SMTP padrão:

Email: admin@dominio.com
Senha: dwwzyd
Autenticação: PLAIN ou LOGIN

4. Portas configuradas:

SMTP: 25, 587 (STARTTLS), 465 (SSL/TLS)
IMAP: 143, 993 (SSL/TLS)
POP3: 110, 995 (SSL/TLS)

5. Página de configuração DNS:

Acessível em: http://IP_DO_SERVIDOR/lesk.html
Contém todos os registros DNS necessários
Botões de copiar individuais
Design responsivo e moderno

6. Logs automáticos gerados:

links_configuracao_[timestamp].txt
smtp_credenciais_compacto_[timestamp].txt
smtp_credenciais_detalhado_[timestamp].txt
