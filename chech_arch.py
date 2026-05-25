import struct
import os

def arch(f):
    if not os.path.exists(f):
        return "NO ENCONTRADO"
    d = open(f, 'rb').read(1024)
    # el offset al PE header esta en 0x3c (campo e_lfanew del DOS header)
    pe_off = struct.unpack_from('<I', d, 0x3c)[0]
    # el campo Machine esta 4 bytes despues de la firma PE
    machine = struct.unpack_from('<H', d, pe_off + 4)[0]
    nombres = {0x8664: 'x64 (64 bits)', 0x14c: 'x86 (32 bits)', 0x200: 'ia64'}
    return nombres.get(machine, 'desconocido: ' + hex(machine))

archivos = [
    'libcrypto-1_1-x64.dll',
    'libssl-1_1-x64.dll',
    'libgcc_s_dw2-1.dll',
    'servidor.exe',
    'cliente.exe',
]

for f in archivos:
    print(f + ': ' + arch(f))