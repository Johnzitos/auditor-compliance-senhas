# Portfólio de Engenharia de Segurança da Informação

Repositório central para ferramentas de segurança ofensiva (Red Team) e defensiva (Blue Team), desenvolvido com foco em automação de tarefas, auditoria de conformidade e scripting.

O objetivo deste portfólio é demonstrar a aplicação prática de conceitos de criptografia, protocolos de rede (TCP/IP), manipulação de sistema operacional (Kernel/Userland) e normas de segurança.

## Índice de Projetos

| ID | Ferramenta | Categoria | Stack Tecnológico | Status |
| :--- | :--- | :--- | :--- | :--- |
| 01 | [Auditor de Compliance de Senhas](./Projeto-01-Auditor-Senha) | GRC / Blue Team | Python, Math, Regex | **Concluído** |
| 02 | [Network Port Scanner](./Projeto-02-PortScanner) | Recon / Red Team | Python, Socket Library | **Concluído** |
| 03 | [Keylogger Multi-Plataforma](./Projeto-03-Keylogger) | Malware Dev / Red Team | Python, Kernel (evdev), WinAPI | **Concluído** |
| 04 | [Network Packet Sniffer](./Projeto-04-Sniffer) | Network / Blue Team | Python, Scapy | Em Desenvolvimento |
**Concluído** |
| 05 | [Web Vuln Scanner](./Projeto-05-VulnScanner) | WebSec / Red Team | Python, BeautifulSoup | - | **Concluído** |
| 06 | [Forensic File Scanner](./Projeto-06-FileSigScanner) | Forensics / Blue Team | Python, JSON | - | **Concluído** |
## Detalhamento Técnico

### Competências Aplicadas
* **Linux Internals:** Interação direta com o subsistema de entrada do Kernel (`/dev/input/`) para contornar isolamento gráfico do Wayland.
* **Redes de Computadores:** Manipulação de sockets puros (Raw Sockets) para varredura de portas e handshake TCP.
* **Scripting Ofensivo:** Desenvolvimento de agentes de monitoramento com persistência e suporte multiplataforma (Windows/Linux).
* **Conformidade (GRC):** Tradução de requisitos de normas (ISO 27001) em lógica de validação de software.
* **Criptografia:** Implementação de entropia de Shannon para análise de força de senhas.

### Stack Tecnológica
* **Linguagens:** Python 3.x, Bash Script.
* **Ambiente:** Linux (Kali/Debian), Windows, Git.
* **Bibliotecas Principais:** `evdev` (Linux Kernel), `pynput` (Hooks), `socket`, `re`, `math`.

---

_Aviso Legal: As ferramentas disponibilizadas neste repositório foram desenvolvidas estritamente para fins educacionais e auditorias autorizadas.
