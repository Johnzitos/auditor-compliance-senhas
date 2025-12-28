# Multi-Platform Keylogger (Educational)

Ferramenta de monitoramento de keystrokes desenvolvida para fins de estudo de comportamento de malware e auditoria de endpoints. Este projeto contém duas implementações distintas para lidar com as diferenças de arquitetura entre Linux e Windows.

## Estrutura do Projeto

| SO | Arquivo | Tecnologia | Descrição Técnica |
| :--- | :--- | :--- | :--- |
| **Linux** | `keylogger_linux.py` | Kernel Input (`evdev`) | Opera em baixo nível lendo `/dev/input/`. Funciona em **Wayland**, X11 e TTY. |
| **Windows** | `keylogger_windows.py` | WinAPI Hooks (`pynput`) | Utiliza hooks de alto nível do sistema para interceptar eventos de entrada. |

---

##  Instruções para Linux
Esta versão foi desenhada para contornar o isolamento gráfico de ambientes modernos (Wayland). Ela ignora a interface gráfica e lê os dados brutos do hardware.

### Requisitos
* Python 3 + Pip
* Permissões de Root (sudo)

### Instalação e Uso
```bash
# 1. Instalar dependências (dentro do venv)
pip install evdev

# 2. Executar (Requer SUDO para acesso ao hardware)
sudo python3 keylogger_linux.py

