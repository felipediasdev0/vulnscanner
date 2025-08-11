🛡️ Web Vulnerability Scanner — OWASP Top 10
🔍 Visão Geral
O Web Vulnerability Scanner é uma ferramenta automatizada projetada para identificar vulnerabilidades críticas em aplicações web, alinhada com o OWASP Top 10, o principal padrão global para riscos de segurança em aplicações web.

Esta solução auxilia profissionais de segurança, desenvolvedores e equipes DevSecOps a detectar e mitigar falhas comuns, reforçando a postura de segurança das aplicações desde os estágios iniciais de desenvolvimento até o ambiente de produção.

⚙️ Funcionalidades Principais
✅ Cobertura Abrangente: Identificação das 10 principais categorias de vulnerabilidades do OWASP Top 10 (2021), incluindo:

🔐 Broken Access Control

🛡️ Cryptographic Failures

🧨 Injection

🏗️ Insecure Design

⚙️ Security Misconfiguration

📦 Vulnerable and Outdated Components

🆔 Identification and Authentication Failures

🔄 Software and Data Integrity Failures

📋 Security Logging and Monitoring Failures

🌐 Server-Side Request Forgery (SSRF)

📄 Relatórios Detalhados: Evidências claras, níveis de severidade e recomendações práticas para correção.

💻 Execução via CLI: Interface intuitiva para integração em pipelines CI/CD e automação.

🌍 Multiplataforma: Compatível com Windows, Linux e macOS.

⚙️ Configuração Flexível: Ajuste parâmetros como timeout, verbosidade e formato da saída.

🛠️ Requisitos
Python 3.8 ou superior

Bibliotecas:

requests

beautifulsoup4

argparse

<img width="1912" height="946" alt="Captura de tela 2025-08-11 151807" src="https://github.com/user-attachments/assets/284e5d5f-8d2f-4319-91ce-9d0980ea7b1a" />

📊 Estrutura do Relatório
O relatório inclui:

Tipo da vulnerabilidade detectada (ex: Injection, Broken Access Control)

URL afetada

Evidências detalhadas

Grau de severidade (baixo, médio, alto, crítico)

Recomendações para mitigação

