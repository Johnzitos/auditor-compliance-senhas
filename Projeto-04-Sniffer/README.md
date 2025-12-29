# Network Traffic Analyzer (Passive Sniffer)

Ferramenta de análise de tráfego de rede passiva desenvolvida em Python com Scapy. Focada em auditoria de segurança (Blue Team), a ferramenta intercepta e classifica metadados de conexões sem interferir no tráfego.

## Funcionalidades
* **Monitoramento DNS:** Identifica resoluções de nomes (Porta 53).
* **Inspeção HTTP:** Extrai URLs, métodos e procura por credenciais em texto claro (Porta 80).
* **Análise TLS/SSL:** Extrai o **SNI (Server Name Indication)** para identificar sites visitados mesmo em conexões HTTPS criptografadas.
* **Logging Automático:** Salva todas as ocorrências em `network_audit.log` com timestamp.

## Estrutura do Código
O projeto utiliza Programação Orientada a Objetos (POO) e Type Hinting para robustez.
* `sniffer.py`: Script principal com a classe `NetworkAnalyzer`.
* Biblioteca `logging`: Para rotação e formatação de logs profissionais.

## Instalação e Uso

### Requisitos
* Python 3.x
* Permissões de Root/Admin (Necessário para modo promíscuo).

### Execução
1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
