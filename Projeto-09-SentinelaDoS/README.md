# Sentinela - Traffic Anomaly & DoS Detector

**Sistema de Monitoramento de Rede Passivo para Detecção de Ataques de Negação de Serviço.**
Utiliza análise estatística de pacotes em janelas de tempo deslizantes para identificar anomalias volumétricas e SYN Floods.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)
![Network](https://img.shields.io/badge/Network-Scapy-red?style=flat)
![Security](https://img.shields.io/badge/Security-IDS-green?style=flat)

---

## Visão Geral

Ataques de Negação de Serviço (DoS) visam indisponibilizar recursos enviando uma quantidade massiva de tráfego (Volumétrico) ou explorando o handshake TCP (SYN Flood). O **Sentinela** atua como um sensor de rede local que:

1.  Captura tráfego em tempo real (raw sockets).
2.  Agrega contadores por IP de origem.
3.  Aplica lógica de *Time Window* (Janela de Tempo) para calcular taxas de pacotes por segundo.
4.  Alerta administradores imediatamente ao detectar desvios do padrão (Baseline).

---

## Arquitetura da Solução

O script opera em **Modo Silencioso (Daemon-like)** para não poluir o terminal de operações, exibindo apenas um *heartbeat* de status e alertas críticos.

### Vetores de Detecção

* **Volumetric Flood:** Monitora a quantidade total de pacotes IP recebidos de uma única fonte. Se exceder `X` pacotes em `Y` segundos, um alerta crítico é gerado.
* **TCP SYN Flood:** Monitora especificamente pacotes com a flag `SYN` ativada (tentativas de iniciar conexão). Altas taxas indicam tentativa de esgotamento de recursos do servidor.

```mermaid
graph TD
    A[Sniffer de Rede] -->|Captura Pacote| B(Callback Processor)
    B --> C{Janela de Tempo Expirou?}
    C -- Sim --> D[Reseta Contadores]
    C -- Não --> E[Incrementa Contador por IP]
    E --> F{Ultrapassou Limite?}
    F -- Sim --> G[ALERTA VISUAL + LOG]
    F -- Não --> H[Aguardar próximo pacote]
