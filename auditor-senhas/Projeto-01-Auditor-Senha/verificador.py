import math
import re

POLITICA_EMPRESA = {
    "tamanho_minimo": 12,
    "requer_maiuscula": True,
    "requer_minuscula": True,
    "requer_numero": True,
    "requer_simbolo": True,
    "proibir_sequencias": True
}

def verificar_padroes_comuns(senha):
    sequencias = ["123", "abc", "qwerty", "admin", "senha", "password"]
    for seq in sequencias:
        if seq in senha.lower():
            return True
    return False

def calcular_entropia(senha):
    pool_size = 0
    if re.search(r'[a-z]', senha): pool_size += 26
    if re.search(r'[A-Z]', senha): pool_size += 26
    if re.search(r'[0-9]', senha): pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', senha): pool_size += 32
    
    if pool_size == 0 or len(senha) == 0: return 0
    return len(senha) * math.log2(pool_size)

def auditar_senha(senha):
    falhas = []
    
    if len(senha) < POLITICA_EMPRESA["tamanho_minimo"]:
        falhas.append(f"[CRÍTICO] Tamanho insuficiente. A política exige {POLITICA_EMPRESA['tamanho_minimo']} caracteres para inviabilizar ataques de força bruta.")

    if POLITICA_EMPRESA["requer_maiuscula"] and not re.search(r'[A-Z]', senha):
        falhas.append("[MÉDIO] Falta letra maiúscula. Necessário para expandir o espaço de busca.")
        
    if POLITICA_EMPRESA["requer_numero"] and not re.search(r'[0-9]', senha):
        falhas.append("[MÉDIO] Falta número. Senhas apenas alfabéticas são vulneráveis a ataques de dicionário simples.")
        
    if POLITICA_EMPRESA["requer_simbolo"] and not re.search(r'[^a-zA-Z0-9]', senha):
        falhas.append("[MÉDIO] Falta caractere especial. Necessário para evitar quebra por rainbow tables comuns.")

    if POLITICA_EMPRESA["proibir_sequencias"] and verificar_padroes_comuns(senha):
        falhas.append("[ALTO] Padrão previsível detectado (ex: '123', 'abc'). Bloqueado por heurística de segurança.")

    entropia = calcular_entropia(senha)
    
    print(f"\n=== RELATÓRIO DE AUDITORIA DE SENHA ===")
    print(f"Senha analisada: {senha}")
    print(f"Entropia Técnica: {entropia:.2f} bits")
    print("-" * 40)

    if len(falhas) == 0:
        print("APROVADA: A senha está em conformidade com a Política de Segurança da Empresa.")
        print("Status: Segura para uso em ambiente corporativo.")
    else:
        print("REPROVADA: A senha viola as seguintes normas de segurança:")
        for falha in falhas:
            print(f"  - {falha}")
        print("\nRecomendação: Ajuste a senha para atender aos requisitos de conformidade.")

if __name__ == "__main__":
    print("=== Auditor de Política de Senhas (Compliance Check) ===")
    print(f"Simulando política: Min {POLITICA_EMPRESA['tamanho_minimo']} chars, Complexidade Ativa.")
    
    while True:
        senha_input = input("\nInsira a senha para auditoria (ou 'q' para sair): ")
        if senha_input == 'q': break
        auditar_senha(senha_input)