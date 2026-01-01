# Automated Web Vulnerability Scanner (DAST)

**Ferramenta de Segurança Ofensiva baseada nas diretrizes OWASP Top 10.**
Automação de Pentest, Análise de Conformidade e Relatórios de Mitigação.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)
![Security](https://img.shields.io/badge/Security-OWASP-red?style=flat&logo=kalilinux)
![Status](https://img.shields.io/badge/Status-Stable-success?style=flat)

---

## Contexto de Negócio

No ciclo de desenvolvimento moderno (DevSecOps), a segurança muitas vezes é negligenciada em prol da velocidade de entrega. Isso gera riscos críticos para a organização:

1.  **Custo da Correção:** Corrigir uma falha em produção possui um custo significativamente maior do que na fase de desenvolvimento.
2.  **Proteção de Dados:** Vulnerabilidades como SQL Injection podem expor bases de dados inteiras, comprometendo a confidencialidade.
3.  **Conformidade Regulatória:** A ausência de controles básicos de segurança pode resultar em violações de leis de proteção de dados (LGPD/GDPR).

A execução de testes manuais é onerosa e não escalável. Este projeto soluciona este problema através da automação da triagem inicial de segurança.

---

## Solução Técnica

Esta ferramenta atua como um **Scanner Dinâmico (DAST)**, simulando o comportamento de um agente malicioso externo. O software navega pela aplicação alvo, mapeia a superfície de ataque e executa testes de intrusão automatizados.

### Capacidades Principais

* **Deep Crawling:** Mapeamento recursivo da estrutura da aplicação web.
* **Detecção de Injeção:** Testes automatizados para identificação de XSS (Cross-Site Scripting) e SQL Injection.
* **Análise de CSRF:** Verificação de integridade em formulários que não implementam tokens anti-falsificação.
* **Auditoria de Infraestrutura:** Identificação de cabeçalhos de segurança ausentes e arquivos sensíveis expostos (ex: .env, .git, backups).
* **Relatórios Técnicos:** Geração de artefatos em HTML contendo a descrição da vulnerabilidade e a respectiva mitigação técnica.

---

## Arquitetura e Fluxo de Execução

O scanner opera através de um pipeline linear composto por cinco estágios:

```mermaid
graph TD
    A[Input: URL Alvo] -->|Request| B(Auditoria de Headers)
    B --> C(Fuzzing de Arquivos)
    C --> D{Crawler Engine}
    D -->|Extração de Links| E[Lista de Endpoints]
    E -->|Extração de Forms| F{Injection Engine}
    F -->|Payload XSS| G[Teste de Vulnerabilidade]
    F -->|Payload SQLi| G
    F -->|Check Token| H[Validação CSRF]
    G --> I[Gerador de Relatório HTML]
    H --> I
