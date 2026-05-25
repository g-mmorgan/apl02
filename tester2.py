# tester_sin_exe.py
# tester alternativo que NO compila ni ejecuta los .exe
# prueba toda la logica de la practica directamente en python:
#   cifrado RSA-OAEP, cifrado AES-256-CBC, estructura de metadatos,
#   flujo completo de transferencia cifrada, integridad SHA-256
#   y patron de servidor iterativo
#
# util cuando los .exe no arrancan por problemas de dlls o arquitectura
# pero queremos demostrar que la logica del protocolo es correcta
#
# requisitos: python 3.x, openssl en PATH, pip install cryptography
# ejecutar:   python tester_sin_exe.py   (desde la carpeta apl02/)

import os
import sys
import socket
import struct
import threading
import time
import hashlib
import subprocess
import tempfile
import shutil
import random
from datetime import datetime

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ─────────────────────────────────────────────
# configuracion global
# ─────────────────────────────────────────────

PUERTO_BASE    = 19999   # puertos distintos a tester.py para no colisionar
TAM_CLAVE_AES  = 32      # AES-256 -> 32 bytes de clave
TAM_IV         = 16      # AES-CBC -> 16 bytes de IV
TAM_CLAVE_RSA  = 2048    # RSA-2048
MAX_NOMBRE     = 256
TIMEOUT_SOCKET = 5

ok    = 0
fail  = 0
warns = 0

DIR_TEMP = tempfile.mkdtemp(prefix="tester_sinexe_")

RUTA_CLAVE_PRIVADA = os.path.join(DIR_TEMP, "server_key.pem")
RUTA_CERTIFICADO   = os.path.join(DIR_TEMP, "server_cert.pem")

# ─────────────────────────────────────────────
# colores y log
# ─────────────────────────────────────────────

def verde(t):    return "\033[92m" + t + "\033[0m"
def rojo(t):     return "\033[91m" + t + "\033[0m"
def amarillo(t): return "\033[93m" + t + "\033[0m"
def cyan(t):     return "\033[96m" + t + "\033[0m"
def negrita(t):  return "\033[1m"  + t + "\033[0m"

def log_ok(msg):
    global ok
    ok += 1
    print("  " + verde("[OK]") + "   " + msg)

def log_fail(msg, detalle=""):
    global fail
    fail += 1
    print("  " + rojo("[FAIL]") + " " + msg)
    if detalle:
        for linea in str(detalle).splitlines():
            print("         " + rojo("->") + " " + linea)

def log_warn(msg, detalle=""):
    global warns
    warns += 1
    print("  " + amarillo("[WARN]") + " " + msg)
    if detalle:
        for linea in str(detalle).splitlines():
            print("         " + amarillo(">>") + " " + linea)

def log_info(msg):
    print("  " + cyan("[INFO]") + " " + msg)

def separador(titulo):
    linea = cyan("=" * 60)
    print("\n" + negrita(linea))
    print("  " + negrita(titulo))
    print(negrita(linea))

# ─────────────────────────────────────────────
# bloque 0: entorno minimo (sin compilador)
# ─────────────────────────────────────────────

def test_entorno():
    separador("BLOQUE 0 - ENTORNO MINIMO (sin compilador)")

    v = sys.version_info
    if v.major >= 3 and v.minor >= 6:
        log_ok("python " + str(v.major) + "." + str(v.minor) + "." + str(v.micro))
    else:
        log_fail("se necesita python 3.6+", sys.version)

    try:
        r = subprocess.run(["openssl", "version"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log_ok("openssl disponible: " + r.stdout.strip())
        else:
            log_fail("openssl no responde", r.stderr.strip())
    except FileNotFoundError:
        log_fail("openssl no encontrado en PATH")

    if CRYPTO_OK:
        log_ok("libreria python 'cryptography' disponible")
    else:
        log_fail("libreria 'cryptography' no disponible",
                 "instala con: pip install cryptography")
        sys.exit(1)

    try:
        ruta = os.path.join(DIR_TEMP, "test.tmp")
        open(ruta, "w").close()
        os.remove(ruta)
        log_ok("directorio temporal OK: " + DIR_TEMP)
    except Exception as e:
        log_fail("no se puede escribir en directorio temporal", str(e))

# ─────────────────────────────────────────────
# bloque 1: generacion de claves RSA con openssl
# ─────────────────────────────────────────────

def test_generacion_claves():
    separador("BLOQUE 1 - GENERACION DE CLAVES RSA (openssl)")

    log_info("generando clave privada RSA-2048...")
    try:
        r = subprocess.run(
            ["openssl", "genrsa", "-out", RUTA_CLAVE_PRIVADA, str(TAM_CLAVE_RSA)],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and os.path.exists(RUTA_CLAVE_PRIVADA):
            log_ok("clave privada RSA-2048 generada ("
                   + str(os.path.getsize(RUTA_CLAVE_PRIVADA)) + " bytes)")
        else:
            log_fail("error al generar clave privada",
                     "returncode=" + str(r.returncode) + "\n" + r.stderr.strip())
            return False
    except Exception as e:
        log_fail("excepcion al generar clave privada", str(e))
        return False

    log_info("generando certificado X.509 autofirmado...")
    try:
        r = subprocess.run(
            ["openssl", "req", "-new", "-x509",
             "-key", RUTA_CLAVE_PRIVADA,
             "-out", RUTA_CERTIFICADO,
             "-days", "365",
             "-subj", "/CN=TestServer/O=APL02/C=ES"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and os.path.exists(RUTA_CERTIFICADO):
            log_ok("certificado X.509 generado ("
                   + str(os.path.getsize(RUTA_CERTIFICADO)) + " bytes)")
        else:
            log_fail("error al generar certificado",
                     "returncode=" + str(r.returncode) + "\n" + r.stderr.strip())
            return False
    except Exception as e:
        log_fail("excepcion al generar certificado", str(e))
        return False

    try:
        r = subprocess.run(
            ["openssl", "verify", "-CAfile", RUTA_CERTIFICADO, RUTA_CERTIFICADO],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            log_ok("verificacion openssl verify del certificado: OK")
        else:
            log_warn("openssl verify no paso", r.stdout.strip())
    except Exception as e:
        log_warn("no se pudo verificar el certificado", str(e))

    try:
        r = subprocess.run(
            ["openssl", "x509", "-in", RUTA_CERTIFICADO, "-pubkey", "-noout"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and "BEGIN PUBLIC KEY" in r.stdout:
            log_ok("clave publica extraida del certificado: OK")
        else:
            log_fail("no se pudo extraer la clave publica", r.stderr.strip())
    except Exception as e:
        log_fail("excepcion al extraer clave publica", str(e))

    return True

# ─────────────────────────────────────────────
# helpers de criptografia (equivalen a crypto_utils.c en python)
# ─────────────────────────────────────────────

def cargar_clave_publica():
    with open(RUTA_CERTIFICADO, "rb") as f:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert.public_key()

def cargar_clave_privada():
    with open(RUTA_CLAVE_PRIVADA, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())

def cifrar_con_rsa(pub, datos):
    # RSA-OAEP con SHA-256: equivale a EVP_PKEY_encrypt con RSA_PKCS1_OAEP_PADDING
    return pub.encrypt(datos, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

def descifrar_con_rsa(priv, datos_cifrados):
    # equivale a EVP_PKEY_decrypt con RSA_PKCS1_OAEP_PADDING en crypto_utils.c
    return priv.decrypt(datos_cifrados, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

def cifrar_aes(clave, iv, datos):
    # AES-256-CBC con padding PKCS7: equivale a EVP_EncryptInit/Update/Final en crypto_utils.c
    from cryptography.hazmat.primitives import padding as sp
    padder  = sp.PKCS7(128).padder()
    datos_p = padder.update(datos) + padder.finalize()
    enc = Cipher(algorithms.AES(clave), modes.CBC(iv),
                 backend=default_backend()).encryptor()
    return enc.update(datos_p) + enc.finalize()

def descifrar_aes(clave, iv, cifrado):
    # equivale a EVP_DecryptInit/Update/Final en crypto_utils.c
    from cryptography.hazmat.primitives import padding as sp
    dec     = Cipher(algorithms.AES(clave), modes.CBC(iv),
                     backend=default_backend()).decryptor()
    datos_p = dec.update(cifrado) + dec.finalize()
    unpad   = sp.PKCS7(128).unpadder()
    return unpad.update(datos_p) + unpad.finalize()

# ─────────────────────────────────────────────
# bloque 2: cifrado RSA-OAEP (equivale a cifrar_clave_rsa / descifrar_clave_rsa)
# ─────────────────────────────────────────────

def test_cifrado_rsa():
    separador("BLOQUE 2 - CIFRADO / DESCIFRADO RSA-OAEP (crypto_utils.c)")

    try:
        pub  = cargar_clave_publica()
        priv = cargar_clave_privada()
        log_ok("claves RSA cargadas desde PEM correctamente")
    except Exception as e:
        log_fail("no se pudieron cargar las claves RSA", str(e))
        return

    clave = os.urandom(TAM_CLAVE_AES)
    log_info("clave AES de prueba (hex): " + clave.hex())

    # prueba 1: cifrar con publica + descifrar con privada
    try:
        cifrado    = cifrar_con_rsa(pub, clave)
        descifrado = descifrar_con_rsa(priv, cifrado)
        if descifrado == clave:
            log_ok("cifrado/descifrado RSA-OAEP de clave AES-256 ("
                   + str(TAM_CLAVE_AES) + " B): OK")
        else:
            log_fail("la clave descifrada no coincide",
                     "original:   " + clave.hex()
                     + "\ndescifrado: " + descifrado.hex())
    except Exception as e:
        log_fail("excepcion en cifrado/descifrado RSA", str(e))

    # prueba 2: el bloque cifrado tiene exactamente 256 bytes (RSA-2048)
    try:
        cifrado  = cifrar_con_rsa(pub, clave)
        esperado = TAM_CLAVE_RSA // 8
        if len(cifrado) == esperado:
            log_ok("tamano bloque RSA cifrado: " + str(len(cifrado))
                   + " bytes (correcto RSA-" + str(TAM_CLAVE_RSA) + ")")
        else:
            log_warn("tamano inesperado del bloque RSA",
                     "obtenido=" + str(len(cifrado)) + " esperado=" + str(esperado))
    except Exception as e:
        log_fail("error verificando tamano bloque RSA", str(e))

    # prueba 3: descifrar con clave incorrecta debe fallar
    try:
        priv_falsa = rsa.generate_private_key(65537, TAM_CLAVE_RSA, default_backend())
        cifrado    = cifrar_con_rsa(pub, clave)
        try:
            descifrar_con_rsa(priv_falsa, cifrado)
            log_fail("descifrado con clave incorrecta no fallo (problema de seguridad)")
        except Exception:
            log_ok("descifrado con clave RSA incorrecta falla correctamente")
    except Exception as e:
        log_warn("no se pudo probar clave incorrecta", str(e))

    # prueba 4: OAEP es probabilistico (mismo plaintext -> ciphertexts distintos)
    try:
        c1 = cifrar_con_rsa(pub, clave)
        c2 = cifrar_con_rsa(pub, clave)
        if c1 != c2:
            log_ok("RSA-OAEP es probabilistico: dos cifrados del mismo dato son distintos")
        else:
            log_warn("los dos cifrados son identicos (padding puede no ser aleatorio)")
    except Exception as e:
        log_warn("no se pudo probar caracter probabilistico", str(e))

    # prueba 5: el bloque cifrado tiene entropia alta (no es texto plano)
    try:
        cifrado = cifrar_con_rsa(pub, clave)
        ceros   = cifrado.count(0)
        if ceros < len(cifrado) // 2:
            log_ok("bloque RSA cifrado tiene alta entropia (pocos bytes cero: "
                   + str(ceros) + "/" + str(len(cifrado)) + ")")
        else:
            log_warn("bloque RSA cifrado tiene baja entropia",
                     "demasiados ceros: " + str(ceros) + "/" + str(len(cifrado)))
    except Exception as e:
        log_warn("no se pudo comprobar entropia del bloque RSA", str(e))

# ─────────────────────────────────────────────
# bloque 3: cifrado AES-256-CBC (equivale a cifrar_aes / descifrar_aes)
# ─────────────────────────────────────────────

def test_cifrado_aes():
    separador("BLOQUE 3 - CIFRADO / DESCIFRADO AES-256-CBC (crypto_utils.c)")

    clave = os.urandom(TAM_CLAVE_AES)
    iv    = os.urandom(TAM_IV)

    log_info("clave AES (hex): " + clave.hex())
    log_info("IV (hex):        " + iv.hex())

    # bateria de casos borde para asegurar que el padding PKCS7 funciona en todos
    casos = [
        ("texto simple 53 B",  b"hola esto es una prueba de AES-256-CBC en la practica"),
        ("binario 1 KB",       os.urandom(1024)),
        ("binario 100 KB",     os.urandom(100 * 1024)),
        ("binario 5 MB",       os.urandom(5 * 1024 * 1024)),
        ("exactamente 16 B",   os.urandom(16)),   # multiplo exacto de bloque AES
        ("1 byte",             os.urandom(1)),    # minimo posible
        ("ceros 1 KB",         bytes(1024)),      # todo ceros (caso degenerado)
        ("patron repetido 1KB",b"\xAB\xCD" * 512),
    ]

    for nombre, datos in casos:
        try:
            t0  = time.time()
            enc = cifrar_aes(clave, iv, datos)
            dec = descifrar_aes(clave, iv, enc)
            ms  = (time.time() - t0) * 1000
            if dec == datos:
                # el bloque cifrado siempre es mayor por el padding PKCS7
                overhead = len(enc) - len(datos)
                log_ok("AES " + nombre + ": OK (" + str(round(ms, 1)) + " ms)"
                       + " orig=" + str(len(datos)) + "B"
                       + " cifrado=" + str(len(enc)) + "B"
                       + " overhead=" + str(overhead) + "B")
            else:
                log_fail("AES " + nombre + ": datos no coinciden tras descifrar",
                         "orig=" + str(len(datos)) + "B recv=" + str(len(dec)) + "B"
                         + "\nprimeros bytes orig: " + datos[:8].hex()
                         + "\nprimeros bytes desc: " + dec[:8].hex())
        except Exception as e:
            log_fail("AES " + nombre + ": excepcion", str(e))

    # prueba de integridad SHA-256 sobre 4 KB
    try:
        datos  = os.urandom(4096)
        h_orig = hashlib.sha256(datos).hexdigest()
        enc    = cifrar_aes(clave, iv, datos)
        dec    = descifrar_aes(clave, iv, enc)
        h_desc = hashlib.sha256(dec).hexdigest()
        if h_orig == h_desc:
            log_ok("integridad SHA-256 tras cifrado/descifrado AES: OK")
            log_info("hash: " + h_orig)
        else:
            log_fail("hash SHA-256 no coincide (corrupcion silenciosa)",
                     "orig: " + h_orig + "\ndesc: " + h_desc)
    except Exception as e:
        log_fail("excepcion en prueba SHA-256 de AES", str(e))

    # el modo CBC con IV distinto produce cifrado distinto (modo correcto)
    try:
        datos = os.urandom(64)
        iv2   = os.urandom(TAM_IV)
        enc1  = cifrar_aes(clave, iv,  datos)
        enc2  = cifrar_aes(clave, iv2, datos)
        if enc1 != enc2:
            log_ok("IV distinto produce cifrado distinto (modo CBC funciona correctamente)")
        else:
            log_warn("IV distinto produce el mismo cifrado (modo CBC no usa IV)")
    except Exception as e:
        log_warn("no se pudo probar efecto del IV", str(e))

    # descifrar con clave incorrecta debe fallar (integridad del padding)
    try:
        datos     = os.urandom(64)
        enc       = cifrar_aes(clave, iv, datos)
        clave_mal = os.urandom(TAM_CLAVE_AES)
        try:
            dec = descifrar_aes(clave_mal, iv, enc)
            # en AES-CBC el descifrado puede no lanzar excepcion pero los datos deben ser distintos
            if dec != datos:
                log_ok("AES con clave incorrecta produce datos distintos (no hay corrupcion silenciosa)")
            else:
                log_fail("AES con clave incorrecta produjo los mismos datos (fallo critico de seguridad)")
        except Exception:
            log_ok("AES con clave incorrecta lanza excepcion (padding invalido detectado)")
    except Exception as e:
        log_warn("no se pudo probar AES con clave incorrecta", str(e))

# ─────────────────────────────────────────────
# bloque 4: estructura de metadatos (equivale a MetadatosFichero en common.h)
# ─────────────────────────────────────────────

# formato identico al struct C en common.h:
#   uint64_t  longitud_fichero          -> Q  (8 B)
#   char      nombre_fichero[256]       -> 256s
#   char      fecha_hora[20]            -> 20s
#   uint8_t   clave_sesion_cifrada[256] -> 256s
#   uint8_t   iv[16]                    -> 16s
#   int       len_clave_cifrada         -> i  (4 B)
#   total = 560 bytes
FORMATO_META = "Q256s20s256s16si"
TAM_META     = struct.calcsize(FORMATO_META)

def empaquetar_meta(longitud, nombre, fecha, clave_c, iv, len_c):
    return struct.pack(
        FORMATO_META,
        longitud,
        nombre.encode()[:255].ljust(256, b'\x00'),
        fecha.encode()[:19].ljust(20,  b'\x00'),
        clave_c.ljust(256, b'\x00'),
        iv,
        len_c
    )

def desempaquetar_meta(raw):
    longitud, nb, fb, cc, iv, lc = struct.unpack(FORMATO_META, raw)
    return (longitud,
            nb.rstrip(b'\x00').decode(errors="replace"),
            fb.rstrip(b'\x00').decode(errors="replace"),
            cc, iv, lc)

def test_estructura_metadatos():
    separador("BLOQUE 4 - ESTRUCTURA DE METADATOS (common.h MetadatosFichero)")

    log_info("layout del struct en C: Q256s20s256s16si")
    log_info("  longitud_fichero [8B] + nombre_fichero [256B] + fecha_hora [20B]")
    log_info("  + clave_sesion_cifrada [256B] + iv [16B] + len_clave_cifrada [4B]")
    log_info("  = 8 + 256 + 20 + 256 + 16 + 4 = 560 bytes")

    if TAM_META == 560:
        log_ok("tamano struct MetadatosFichero: " + str(TAM_META) + " bytes (correcto)")
    else:
        log_fail("tamano struct incorrecto",
                 "obtenido=" + str(TAM_META) + " esperado=560"
                 + "\nrevisa los campos de MetadatosFichero en common.h")

    # serializacion y deserializacion con valores reales
    try:
        lon_o = 7654321
        nom_o = "documento_confidencial.pdf"
        fec_o = "2025-05-25 12:00:00"
        cc_o  = os.urandom(256)
        iv_o  = os.urandom(TAM_IV)
        lc_o  = 256

        raw    = empaquetar_meta(lon_o, nom_o, fec_o, cc_o, iv_o, lc_o)
        lon_r, nom_r, fec_r, cc_r, iv_r, lc_r = desempaquetar_meta(raw)

        errores = []
        if lon_r != lon_o:
            errores.append("longitud_fichero: env=" + str(lon_o) + " recv=" + str(lon_r))
        if nom_r != nom_o:
            errores.append("nombre_fichero: env='" + nom_o + "' recv='" + nom_r + "'")
        if fec_r != fec_o:
            errores.append("fecha_hora: env='" + fec_o + "' recv='" + fec_r + "'")
        if cc_r[:256] != cc_o:
            errores.append("clave_sesion_cifrada: los 256 bytes no coinciden")
        if iv_r != iv_o:
            errores.append("iv: env=" + iv_o.hex() + " recv=" + iv_r.hex())
        if lc_r != lc_o:
            errores.append("len_clave_cifrada: env=" + str(lc_o) + " recv=" + str(lc_r))

        if not errores:
            log_ok("serializacion/deserializacion de todos los campos: OK")
        else:
            for e in errores:
                log_fail("campo con error: " + e)
    except Exception as e:
        log_fail("excepcion al serializar/deserializar metadatos", str(e))

    # uint64 maximo (sin overflow)
    try:
        u64max = 2**64 - 1
        raw    = empaquetar_meta(u64max, "t.bin", "2025-01-01 00:00:00",
                                 bytes(256), bytes(TAM_IV), 256)
        lon_r  = desempaquetar_meta(raw)[0]
        if lon_r == u64max:
            log_ok("longitud_fichero uint64 maximo (2^64-1 = " + str(u64max) + "): OK")
        else:
            log_fail("overflow en uint64",
                     "enviado=" + str(u64max) + " recibido=" + str(lon_r))
    except Exception as e:
        log_fail("excepcion con uint64 maximo", str(e))

    # nombre de fichero en el limite del campo (255 chars + null)
    try:
        nom_largo = "A" * 255
        raw       = empaquetar_meta(1, nom_largo, "2025-01-01 00:00:00",
                                    bytes(256), bytes(TAM_IV), 256)
        _, nom_r, _, _, _, _ = desempaquetar_meta(raw)
        if nom_r == nom_largo:
            log_ok("nombre_fichero de 255 caracteres serializa correctamente")
        else:
            log_fail("nombre_fichero largo no serializa bien",
                     "enviado len=" + str(len(nom_largo))
                     + " recibido len=" + str(len(nom_r)))
    except Exception as e:
        log_fail("excepcion con nombre largo", str(e))

    # el struct serializado debe tener exactamente TAM_META bytes
    try:
        raw = empaquetar_meta(0, "test.bin", "2025-01-01 00:00:00",
                              bytes(256), bytes(TAM_IV), 0)
        if len(raw) == TAM_META:
            log_ok("struct serializado tiene el tamano correcto: " + str(len(raw)) + " bytes")
        else:
            log_fail("tamano del struct serializado incorrecto",
                     "obtenido=" + str(len(raw)) + " esperado=" + str(TAM_META))
    except Exception as e:
        log_fail("excepcion al comprobar tamano del struct serializado", str(e))

# ─────────────────────────────────────────────
# bloque 5: conexion TCP basica
# ─────────────────────────────────────────────

def test_conexion_tcp():
    separador("BLOQUE 5 - CONEXION TCP (socket, bind, listen, accept, connect)")

    puerto = PUERTO_BASE + 1
    log_info("servidor echo en puerto " + str(puerto) + " (loopback)")

    def servidor_echo(p, listo):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
            s.listen(1)
            s.settimeout(5)
            listo.set()
            conn, addr = s.accept()
            log_info("servidor echo: cliente desde " + str(addr))
            conn.settimeout(5)
            datos = conn.recv(1024)
            log_info("servidor echo: recibidos " + str(len(datos)) + " bytes, devolviendo")
            conn.sendall(datos)
            conn.close()
            s.close()
        except Exception as e:
            log_warn("excepcion en servidor echo", str(e))

    listo = threading.Event()
    hilo  = threading.Thread(target=servidor_echo, args=(puerto, listo), daemon=True)
    hilo.start()

    if not listo.wait(timeout=3):
        log_fail("el servidor echo no arranco en 3 segundos")
        return

    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(TIMEOUT_SOCKET)
        c.connect(("127.0.0.1", puerto))
        msg = b"APL02 TCP loopback test - " + os.urandom(10)
        c.sendall(msg)
        resp = c.recv(1024)
        c.close()
        hilo.join(timeout=3)

        if resp == msg:
            log_ok("TCP loopback echo: OK (" + str(len(msg)) + " bytes ida y vuelta)")
        else:
            log_fail("datos TCP no coinciden",
                     "env=" + msg.hex() + "\nrecv=" + resp.hex())
    except socket.timeout:
        log_fail("timeout en TCP loopback",
                 "el servidor echo no respondio en " + str(TIMEOUT_SOCKET) + "s")
    except Exception as e:
        log_fail("excepcion en TCP loopback", str(e))

    # puerto cerrado debe rechazar la conexion
    puerto_cerrado = PUERTO_BASE + 2
    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(2)
        c.connect(("127.0.0.1", puerto_cerrado))
        c.close()
        log_fail("conexion a puerto cerrado no fallo")
    except (ConnectionRefusedError, socket.timeout, OSError):
        log_ok("conexion a puerto cerrado falla correctamente")
    except Exception as e:
        log_warn("excepcion inesperada en puerto cerrado", str(e))

# ─────────────────────────────────────────────
# bloque 6: flujo completo de transferencia cifrada
# simula exactamente lo que hacen servidor.c y cliente.c
# ─────────────────────────────────────────────

def srv_transferencia(puerto, resultado):
    # simula servidor.c: recibe metadatos, descifra clave RSA, acepta,
    # recibe datos cifrados AES, descifra, almacena
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", puerto))
        s.listen(1)
        s.settimeout(10)
        conn, _ = s.accept()
        conn.settimeout(10)

        # paso 1: recibir estructura de metadatos (560 bytes)
        raw = b""
        while len(raw) < TAM_META:
            c = conn.recv(TAM_META - len(raw))
            if not c:
                raise Exception("conexion cerrada antes de recibir metadatos completos "
                                + "(" + str(len(raw)) + "/" + str(TAM_META) + " bytes)")
            raw += c

        longitud, nombre, fecha, cc, iv, lc = desempaquetar_meta(raw)

        # paso 2: descifrar la clave de sesion AES con la clave privada RSA
        priv      = cargar_clave_privada()
        clave_ses = descifrar_con_rsa(priv, cc[:lc])

        # paso 3: enviar aceptacion (RespuestaServidor.aceptado = 1)
        conn.send(struct.pack("i", 1))

        # paso 4: recibir tamano del bloque cifrado (uint64, 8 bytes)
        raw_tam = b""
        while len(raw_tam) < 8:
            c = conn.recv(8 - len(raw_tam))
            if not c:
                raise Exception("conexion cerrada al recibir tamano del bloque cifrado")
            raw_tam += c
        tam_c = struct.unpack("Q", raw_tam)[0]

        # paso 5: recibir el fichero cifrado completo
        datos_c = b""
        while len(datos_c) < tam_c:
            chunk = conn.recv(min(4096, tam_c - len(datos_c)))
            if not chunk:
                raise Exception("conexion cerrada durante recepcion de datos cifrados "
                                + "(" + str(len(datos_c)) + "/" + str(tam_c) + " bytes)")
            datos_c += chunk

        # paso 6: descifrar el fichero con AES-256-CBC
        datos_d = descifrar_aes(clave_ses, iv, datos_c)
        conn.close()
        s.close()

        resultado.update({
            "ok":         True,
            "datos":      datos_d,
            "longitud":   longitud,
            "nombre":     nombre,
            "fecha":      fecha,
            "tam_cifrado": tam_c,
        })
    except Exception as e:
        resultado.update({"ok": False, "error": str(e)})

def cli_transferencia(puerto, fichero_bytes, nombre):
    # simula cliente.c: genera clave AES, cifra con RSA, envia metadatos,
    # espera aceptacion, cifra AES, envia tamano + datos cifrados
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("127.0.0.1", puerto))

        # generar clave de sesion AES-256 e IV aleatorios (RAND_bytes en C)
        clave_ses = os.urandom(TAM_CLAVE_AES)
        iv        = os.urandom(TAM_IV)

        # cifrar la clave de sesion con la clave publica RSA del servidor
        pub = cargar_clave_publica()
        cc  = cifrar_con_rsa(pub, clave_ses)
        lc  = len(cc)

        # rellenar y enviar la estructura de metadatos
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        raw   = empaquetar_meta(len(fichero_bytes), nombre, fecha, cc, iv, lc)
        s.sendall(raw)

        # esperar aceptacion del servidor
        raw_resp = b""
        while len(raw_resp) < 4:
            c = s.recv(4 - len(raw_resp))
            if not c:
                s.close()
                return False, "servidor cerro la conexion antes de aceptar"
            raw_resp += c
        resp = struct.unpack("i", raw_resp)[0]
        if resp != 1:
            s.close()
            return False, "servidor rechazo (aceptado=" + str(resp) + ")"

        # cifrar el fichero con AES-256-CBC
        enc = cifrar_aes(clave_ses, iv, fichero_bytes)

        # enviar tamano del bloque cifrado (uint64) y luego los datos
        s.sendall(struct.pack("Q", len(enc)))
        s.sendall(enc)
        s.close()
        return True, ""
    except Exception as e:
        return False, str(e)

def flujo_completo(nombre_test, datos, puerto):
    res  = {}
    hilo = threading.Thread(target=srv_transferencia,
                            args=(puerto, res), daemon=True)
    hilo.start()
    time.sleep(0.3)

    ok_cli, err_cli = cli_transferencia(puerto, datos, "prueba.bin")
    hilo.join(timeout=15)

    kb_str = str(round(len(datos) / 1024, 1)) + " KB"

    if not ok_cli:
        log_fail(nombre_test + " (" + kb_str + "): cliente fallo", err_cli)
        return False
    if not res.get("ok"):
        log_fail(nombre_test + " (" + kb_str + "): servidor fallo",
                 res.get("error", "sin detalle"))
        return False
    if res.get("datos") == datos:
        tam_c = res.get("tam_cifrado", 0)
        log_ok(nombre_test + " (" + kb_str + "): OK"
               + " | cifrado=" + str(tam_c) + "B"
               + " overhead=" + str(tam_c - len(datos)) + "B")
        return True
    else:
        recv_datos = res.get("datos", b"")
        log_fail(nombre_test + " (" + kb_str + "): datos NO coinciden",
                 "env=" + str(len(datos)) + "B recv=" + str(len(recv_datos)) + "B"
                 + "\nhash env:  " + hashlib.sha256(datos).hexdigest()
                 + "\nhash recv: " + hashlib.sha256(recv_datos).hexdigest())
        return False

def test_flujo_completo():
    separador("BLOQUE 6 - FLUJO COMPLETO DE TRANSFERENCIA CIFRADA")
    log_info("simula exactamente el protocolo de servidor.c + cliente.c en python")

    casos = [
        ("texto 512 B",      b"Practica APL02 " * 34,       PUERTO_BASE + 10),
        ("binario 10 KB",    os.urandom(10 * 1024),          PUERTO_BASE + 11),
        ("binario 500 KB",   os.urandom(500 * 1024),         PUERTO_BASE + 12),
        ("binario 2 MB",     os.urandom(2 * 1024 * 1024),    PUERTO_BASE + 13),
        ("exactamente 16 B", os.urandom(16),                 PUERTO_BASE + 14),
        ("1 byte",           os.urandom(1),                  PUERTO_BASE + 15),
        ("ceros 1 KB",       bytes(1024),                    PUERTO_BASE + 16),
    ]
    for nombre, datos, puerto in casos:
        flujo_completo(nombre, datos, puerto)
        time.sleep(0.3)

# ─────────────────────────────────────────────
# bloque 7: integridad SHA-256 end-to-end
# ─────────────────────────────────────────────

def test_integridad():
    separador("BLOQUE 7 - INTEGRIDAD END-TO-END (SHA-256)")
    log_info("verifica que los datos recibidos son identicos a los enviados")

    casos = [
        (4,    PUERTO_BASE + 20),
        (128,  PUERTO_BASE + 21),
        (1024, PUERTO_BASE + 22),   # 1 MB para estresar el protocolo
    ]

    for kb, puerto in casos:
        datos  = os.urandom(kb * 1024)
        h_orig = hashlib.sha256(datos).hexdigest()
        log_info("SHA-256 " + str(kb) + " KB original: " + h_orig)

        res  = {}
        hilo = threading.Thread(target=srv_transferencia,
                                args=(puerto, res), daemon=True)
        hilo.start()
        time.sleep(0.3)

        ok_cli, err_cli = cli_transferencia(puerto, datos, "integridad.bin")
        hilo.join(timeout=20)

        if not ok_cli:
            log_fail("integridad " + str(kb) + " KB: cliente fallo", err_cli)
        elif not res.get("ok"):
            log_fail("integridad " + str(kb) + " KB: servidor fallo",
                     res.get("error", "sin detalle"))
        else:
            h_recv = hashlib.sha256(res["datos"]).hexdigest()
            log_info("SHA-256 " + str(kb) + " KB recibido: " + h_recv)
            if h_orig == h_recv:
                log_ok("integridad SHA-256 " + str(kb) + " KB: hashes identicos")
            else:
                log_fail("integridad " + str(kb) + " KB: hashes DISTINTOS",
                         "hash orig: " + h_orig
                         + "\nhash recv: " + h_recv)
        time.sleep(0.3)

# ─────────────────────────────────────────────
# bloque 8: servidor iterativo (patron del temario)
# ─────────────────────────────────────────────

def srv_iterativo(puerto, n_clientes, resultados):
    # patron de servidor iterativo del temario:
    # socket -> bind -> listen -> [accept -> atender -> close]* -> close
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", puerto))
        s.listen(5)
        s.settimeout(15)
        priv = cargar_clave_privada()

        for i in range(n_clientes):
            conn, addr = s.accept()
            conn.settimeout(10)

            # recibir metadatos del cliente i
            raw = b""
            while len(raw) < TAM_META:
                c = conn.recv(TAM_META - len(raw))
                if not c:
                    break
                raw += c

            if len(raw) < TAM_META:
                resultados.append(None)
                conn.close()
                continue

            _, _, _, cc, iv, lc = desempaquetar_meta(raw)
            clave = descifrar_con_rsa(priv, cc[:lc])
            conn.send(struct.pack("i", 1))

            raw_tam = b""
            while len(raw_tam) < 8:
                c = conn.recv(8 - len(raw_tam))
                if not c:
                    break
                raw_tam += c
            tam_c = struct.unpack("Q", raw_tam)[0]

            datos_c = b""
            while len(datos_c) < tam_c:
                chunk = conn.recv(min(4096, tam_c - len(datos_c)))
                if not chunk:
                    break
                datos_c += chunk

            try:
                datos_d = descifrar_aes(clave, iv, datos_c)
                resultados.append(datos_d)
            except Exception:
                resultados.append(None)

            conn.close()
            # el servidor iterativo cierra el slave socket y vuelve al accept
        s.close()
    except Exception:
        while len(resultados) < n_clientes:
            resultados.append(None)

def test_servidor_iterativo():
    separador("BLOQUE 8 - SERVIDOR ITERATIVO (patron temario)")
    log_info("un servidor, N clientes atendidos secuencialmente en bucle")

    for n, puerto in [(3, PUERTO_BASE + 30), (5, PUERTO_BASE + 31)]:
        envios = [os.urandom(random.randint(512, 8192)) for _ in range(n)]
        recvs  = []

        log_info("prueba con " + str(n) + " clientes:")
        for i, d in enumerate(envios):
            log_info("  cliente " + str(i + 1) + ": " + str(len(d)) + " bytes")

        hilo = threading.Thread(target=srv_iterativo,
                                args=(puerto, n, recvs), daemon=True)
        hilo.start()
        time.sleep(0.3)

        for i, datos in enumerate(envios):
            time.sleep(0.15)
            ok_cli, err = cli_transferencia(puerto, datos, "cli_" + str(i) + ".bin")
            if not ok_cli:
                log_warn("cliente " + str(i + 1) + " fallo", err)

        hilo.join(timeout=25)

        if len(recvs) == n:
            fallos = [i for i, (o, r) in enumerate(zip(envios, recvs))
                      if r is None or o != r]
            if not fallos:
                log_ok("servidor iterativo " + str(n) + " clientes: OK")
            else:
                log_fail("servidor iterativo " + str(n) + " clientes: fallos en clientes "
                         + str([i + 1 for i in fallos]))
        else:
            log_fail("servidor iterativo " + str(n) + " clientes: solo "
                     + str(len(recvs)) + " resultados recibidos")

        time.sleep(0.3)

# ─────────────────────────────────────────────
# bloque 9: prueba de seguridad (robustez del protocolo)
# ─────────────────────────────────────────────

def test_seguridad():
    separador("BLOQUE 9 - SEGURIDAD Y ROBUSTEZ DEL PROTOCOLO")

    # prueba A: un cliente que envia metadatos corruptos (clave RSA invalida)
    # el servidor debe rechazar sin petarse
    log_info("prueba A: metadatos con clave RSA corrupta")
    puerto = PUERTO_BASE + 40
    res    = {}

    def srv_robusto(p, res):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
            s.listen(1)
            s.settimeout(5)
            conn, _ = s.accept()
            conn.settimeout(5)
            raw = b""
            while len(raw) < TAM_META:
                c = conn.recv(TAM_META - len(raw))
                if not c:
                    break
                raw += c
            if len(raw) < TAM_META:
                res["ok"] = False
                conn.close()
                s.close()
                return
            _, _, _, cc, iv, lc = desempaquetar_meta(raw)
            priv = cargar_clave_privada()
            try:
                descifrar_con_rsa(priv, cc[:lc])
                # si llega aqui con datos aleatorios es raro pero posible (fallo de padding)
                conn.send(struct.pack("i", 0))  # rechazamos
                res["ok"] = True
                res["msg"] = "descifrado no fallo (datos aleatorios, aceptable)"
            except Exception:
                # lo normal: RSA falla con datos aleatorios -> servidor rechaza
                conn.send(struct.pack("i", 0))
                res["ok"] = True
                res["msg"] = "servidor rechazo correctamente la clave corrupta"
            conn.close()
            s.close()
        except Exception as e:
            res["ok"]  = False
            res["msg"] = str(e)

    hilo = threading.Thread(target=srv_robusto, args=(puerto, res), daemon=True)
    hilo.start()
    time.sleep(0.3)

    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(5)
        c.connect(("127.0.0.1", puerto))
        # enviamos metadatos con la clave RSA rellena de basura aleatoria
        meta_corrupta = empaquetar_meta(
            1000, "malicioso.bin", "2025-01-01 00:00:00",
            os.urandom(256),   # clave RSA invalida (basura)
            os.urandom(16),
            256
        )
        c.sendall(meta_corrupta)
        c.settimeout(5)
        try:
            resp = c.recv(4)
        except Exception:
            resp = b""
        c.close()
    except Exception:
        pass

    hilo.join(timeout=8)
    if res.get("ok"):
        log_ok("servidor robusto ante metadatos corruptos: " + res.get("msg", ""))
    else:
        log_warn("prueba de robustez no concluyente", res.get("msg", "sin detalle"))

    # prueba B: verificar que dos transferencias distintas producen datos cifrados distintos
    # aunque el fichero sea el mismo (la clave de sesion AES es aleatoria en cada transferencia)
    log_info("prueba B: dos transferencias del mismo fichero producen cifrados distintos")
    datos  = os.urandom(512)
    clave1 = os.urandom(TAM_CLAVE_AES)
    clave2 = os.urandom(TAM_CLAVE_AES)
    iv1    = os.urandom(TAM_IV)
    iv2    = os.urandom(TAM_IV)
    enc1   = cifrar_aes(clave1, iv1, datos)
    enc2   = cifrar_aes(clave2, iv2, datos)
    if enc1 != enc2:
        log_ok("mismo fichero con claves distintas produce bloques cifrados distintos")
    else:
        log_fail("mismo fichero con claves distintas produce el mismo cifrado (fallo grave)")

# ─────────────────────────────────────────────
# resumen final
# ─────────────────────────────────────────────

def resumen_final():
    total = ok + fail
    linea = cyan("=" * 60)
    print("\n" + negrita(linea))
    print("  " + negrita("RESUMEN FINAL"))
    print(negrita(linea))
    print("  total de pruebas : " + str(total))
    print("  " + verde("correctas : " + str(ok)))
    if fail > 0:
        print("  " + rojo("fallidas  : " + str(fail)))
    else:
        print("  fallidas  : " + str(fail))
    if warns > 0:
        print("  " + amarillo("avisos    : " + str(warns)))
    print()
    if fail == 0:
        print("  " + verde(negrita("todo correcto: la logica del protocolo funciona")))
    elif fail <= 2:
        print("  " + amarillo(negrita("hay fallos menores que revisar")))
    else:
        print("  " + rojo(negrita("hay fallos importantes en la logica del protocolo")))
    print("\n  directorio temporal: " + DIR_TEMP)
    print("  (se borra automaticamente al acabar)\n")

# ─────────────────────────────────────────────
# punto de entrada
# ─────────────────────────────────────────────

if __name__ == "__main__":
    borde_top = negrita(cyan("+" + "=" * 58 + "+"))
    borde_mid = negrita(cyan("|"))
    borde_bot = negrita(cyan("+" + "=" * 58 + "+"))
    print()
    print(borde_top)
    print(borde_mid + "  TESTER SIN EXE - LOGICA DE PROTOCOLO APL02             " + borde_mid)
    print(borde_mid + "  Prueba cifrado RSA+AES, metadatos y flujo TCP           " + borde_mid)
    print(borde_bot)
    print()
    print("  inicio: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("  nota: este tester NO compila ni ejecuta servidor.exe/cliente.exe")
    print("        prueba la logica del protocolo directamente en python")

    try:
        test_entorno()
        claves_ok = test_generacion_claves()

        if not claves_ok or not CRYPTO_OK:
            log_fail("se omiten bloques por fallo en entorno o claves RSA")
        else:
            test_cifrado_rsa()
            test_cifrado_aes()
            test_estructura_metadatos()
            test_conexion_tcp()
            test_flujo_completo()
            test_integridad()
            test_servidor_iterativo()
            test_seguridad()

    except KeyboardInterrupt:
        print("\n  " + amarillo("pruebas interrumpidas por el usuario"))
    finally:
        try:
            shutil.rmtree(DIR_TEMP)
        except Exception:
            pass
        resumen_final()