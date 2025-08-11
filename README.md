🛡️ Web Vulnerability Scanner — OWASP Top 10
Ferramenta automatizada para identificação de vulnerabilidades críticas em aplicações web, baseada no padrão global OWASP Top 10 (2021). Ideal para profissionais de segurança, desenvolvedores e equipes DevSecOps que buscam reforçar a segurança desde o desenvolvimento até a produção.

🔍 Visão Geral
O Web Vulnerability Scanner realiza varreduras inteligentes em aplicações web, detectando falhas comuns e fornecendo relatórios detalhados com evidências, severidade e recomendações práticas de mitigação.

⚙️ Funcionalidades
- ✅ Cobertura OWASP Top 10 (2021)
Detecta as 10 principais categorias de vulnerabilidades:
- 🔐 Broken Access Control
- 🛡️ Cryptographic Failures
- 🧨 Injection
- 🏗️ Insecure Design
- ⚙️ Security Misconfiguration
- 📦 Vulnerable and Outdated Components
- 🆔 Identification and Authentication Failures
- 🔄 Software and Data Integrity Failures
- 📋 Security Logging and Monitoring Failures
- 🌐 Server-Side Request Forgery (SSRF)
- 📄 Relatórios Detalhados
Evidências claras, grau de severidade (baixo, médio, alto, crítico) e recomendações para correção.
- 💻 Execução via CLI
Interface intuitiva para integração em pipelines CI/CD e automação de testes.
- 🌍 Multiplataforma
Compatível com Windows, Linux e macOS.
- ⚙️ Configuração Flexível
Ajuste de parâmetros como timeout, verbosidade e formato da saída.

🛠️ Requisitos
- Python 3.8 ou superior
- Bibliotecas necessárias:
pip install requests beautifulsoup4 argparse

<img width="1912" height="946" alt="Captura de tela 2025-08-11 151807" src="https://github.com/user-attachments/assets/56f78e2d-4919-4f92-84e8-7b0aca327c8e" />


📊 Estrutura do Relatório
Cada relatório gerado inclui:

| Campo | Descrição | 

| 🧩 Tipo de Vulnerabilidade | Ex: Injection, Broken Access Control | 

| 🔗 URL Afetada | Endereço onde a falha foi detectada | 

| 🧾 Evidências Técnicas | Detalhes da vulnerabilidade | 

| 🚨 Severidade | Baixo, Médio, Alto ou Crítico | 

| 🛠️ Recomendações | Sugestões práticas para mitigação | 
