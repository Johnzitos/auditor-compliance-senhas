# IntegrityGuard: Enterprise File Security Suite

**Suite de Segurança da Informação para Confidencialidade e Integridade de Arquivos.**
Implementação de Criptografia Híbrida e Assinaturas Digitais para Cadeia de Custódia.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)
![Security](https://img.shields.io/badge/Security-RSA_2048_%7C_AES-red?style=flat)
![Compliance](https://img.shields.io/badge/Status-Production_Ready-success?style=flat)

---

## Contexto de Negócio

Em fluxos de trabalho corporativos e governamentais, a tramitação de documentos sensíveis enfrenta vulnerabilidades críticas que métodos tradicionais não mitigam:

1.  **Violação de Integridade:** Risco de interceptação e alteração de arquivos (ataques Man-in-the-Middle) durante o trânsito entre departamentos.
2.  **Repúdio:** A impossibilidade de provar matematicamente a autoria de um documento ou a aprovação de uma etapa de processo.
3.  **Espionagem Industrial:** A exposição de dados confidenciais em redes não seguras sem a devida camada de ofuscação.

A ausência de controles criptográficos robustos compromete a validade jurídica de processos digitais. Este projeto soluciona este problema através de uma infraestrutura de chaves públicas (PKI) descentralizada.

---

## Solução Técnica

O IntegrityGuard atua como uma ferramenta de **Segurança Zero-Knowledge**, onde as chaves privadas nunca deixam o dispositivo do usuário. O sistema implementa **Criptografia Híbrida** para aliar performance e segurança:

### Capacidades Principais

* **Assinatura Digital (RSA-SHA256):** Garante a autenticidade e o não-repúdio. Cria um hash único do arquivo assinado com a chave privada, permitindo validação pública de integridade.
* **Criptografia Simétrica (Fernet/AES):** Utilizada para cifrar o conteúdo do arquivo (payload) com alta velocidade.
* **Encapsulamento de Chave (KEM):** A chave simétrica é cifrada com a chave pública RSA do destinatário, garantindo que apenas o portador da chave privada correspondente possa decifrar o envelope digital.
* **Verificação de Cadeia:** Suporte a múltiplas assinaturas em versões incrementais de documentos, estabelecendo uma trilha de auditoria completa.

---

## Arquitetura e Fluxo de Execução

O sistema foi desenhado para suportar o ciclo de vida completo de documentos seguros, desde a criação até a aprovação final:

```mermaid
graph TD
    classDef actor fill:#f9f9f9,stroke:#333,stroke-width:3px,color:black;
    classDef doc fill:#fff2cc,stroke:#d6b656,stroke-dasharray: 5 5,color:black;
    classDef privateAction fill:#ffcccc,stroke:#b30000,color:black;
    classDef publicAction fill:#d4edda,stroke:#28a745,color:black;
    classDef package fill:#e1e1e1,stroke:#333,color:black;

    Sender((Remetente)):::actor
    Dest1((Destinatário 1\nEditor)):::actor
    Dest2((Destinatário 2\nEditor)):::actor
    Final((Destinatário\nFinal)):::actor

    subgraph Estágio 1: Criação
        Sender -->|1. Cria| Doc1[Documento V1\nOriginal]:::doc
        Doc1 --> Sign1[2. Assina com\nChave Privada do Remetente]:::privateAction
        Sign1 --> Pack1[Pacote 1:\nDoc V1 + Assinatura V1]:::package
    end
    Pack1 ===>|Envia para| Dest1

    subgraph Estágio 2: Modificação e Re-assinatura
        Dest1 -->|3. Recebe| Pack1
        Pack1 --> Verify1[4. Verifica V1 usando\nChave Pública do Remetente]:::publicAction
        Verify1 -->|Integridade OK! -> 5. Edita| Doc2[Documento V2\nModificado por Dest1]:::doc
        Doc2 --> Sign2[6. Assina V2 com\nChave Privada do Dest1]:::privateAction
        Sign2 --> Pack2[Pacote 2:\nDoc V2 + Assinatura V2]:::package
    end
    Pack2 ===>|Envia para| Dest2
