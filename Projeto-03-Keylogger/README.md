# Linux Kernel Keylogger (Wayland/X11 Support)

Ferramenta de monitoramento de input desenvolvida em Python que opera no nível do Kernel do Linux, contornando as restrições de isolamento de janelas impostas por compositores gráficos modernos como o Wayland.

## Diferencial Técnico
Diferente de keyloggers tradicionais baseados em bibliotecas de alto nível (como `pynput` ou `Xlib`) que falham em sessões Wayland, esta ferramenta interage diretamente com os dispositivos de caracteres em `/dev/input/`.

* **Abordagem:** Leitura direta de eventos `EV_KEY` via `ioctl`.
* **Compatibilidade:** Funciona em **X11**, **Wayland** e terminais puros (**TTY**).
* **Dependência:** Biblioteca `evdev` (bindings para o subsistema de input do kernel Linux).

## Funcionalidades
* Detecção e leitura do dispositivo de teclado (`/dev/input/eventX`).
* Captura de keystrokes em background.
* Salvamento de logs com timestamp preciso.

## Instalação e Uso

### Pré-requisitos
* Linux (Kali, Debian, Ubuntu).
* Permissões de Superusuário (Root) - Necessário para ler `/dev/input/`.

### Execução
```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Executar (Requer SUDO devido ao acesso direto ao hardware)
sudo python3 logger_kernel.py
