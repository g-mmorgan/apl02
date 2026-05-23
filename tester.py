# tester exhaustivo para la practica APL02
# prueba todo el flujo: generacion de claves RSA, cifrado AES, conexion TCP,
# transferencia de metadatos y fichero cifrado, y descifrado en el servidor
#
# requisitos: python 3.x + openssl en el PATH
# ejecutar: python tester_practica.py

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
import string
from datetime import datetime

# intentar importar cryptography, si no esta instalada la instalamos
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ─────────────────────────────────────────────
# configuracion global del tester
# ─────────────────────────────────────────────

PUERTO_TEST     = 9999       # puerto para las pruebas de socket
TAM_CLAVE_AES   = 32         # AES-256 -> 32 bytes
TAM_IV          = 16         # IV para AES-CBC
TAM_CLAVE_RSA   = 2048       # bits de la clave RSA
MAX_NOMBRE      = 256        # tamano maximo del nombre de fichero
TIMEOUT_SOCKET  = 5          # segundos de timeout en operaciones de socket

# contadores globales de resultado
ok    = 0
fail  = 0
warns = 0

# directorio temporal para los ficheros de prueba
DIR_TEMP = tempfile.mkdtemp(prefix="tester_apl02_")

# ─────────────────────────────────────────────
# utilidades de salida en consola con colores
# ─────────────────────────────────────────────

def verde(texto):
    return f"\033[92m{texto}\033[0m"

def rojo(texto):
    return f"\033[91m{texto}\033[0m"

def amarillo(texto):
    return f"\033[93m{texto}\033[0m"

def cyan(texto):
    return f"\033[96m{texto}\033[0m"

def negrita(texto):
    return f"\033[1m{texto}\033[0m"

def log_ok(msg):
    global ok
    ok += 1
    print(f"  {verde('[OK]')}   {msg}")

def log_fail(msg, detalle=""):
    global fail
    fail += 1
    linea = f"  {rojo('[FAIL]')} {msg}"
    if detalle:
        linea += f"\n         {rojo('→')} {detalle}"
    print(linea)

def log_warn(msg):
    global warns
    warns += 1
    print(f"  {amarillo('[WARN]')} {msg}")

def log_info(msg):
    print(f"  {cyan('[INFO]')} {msg}")

def separador(titulo):
    print(f"\n{negrita(cyan('═' * 55))}")
    print(f"  {negrita(titulo)}")
    print(f"{negrita(cyan('═' * 55))}")

# ─────────────────────────────────────────────
# bloque 0: comprobacion del entorno
# ─────────────────────────────────────────────

def test_entorno():
    separador("BLOQUE 0 — COMPROBACION DEL ENTORNO")

    # comprobar version de python
    version = sys.version_info
    if version.major >= 3 and version.minor >= 6:
        log_ok(f"python {version.major}.{version.minor}.{version.micro} detectado")
    else:
        log_fail("se necesita python 3.6 o superior", f"version actual: {sys.version}")

    # comprobar que openssl esta en el PATH
    try:
        resultado = subprocess.run(
            ["openssl", "version"],
            capture_output=True, text=True, timeout=5
        )
        if resultado.returncode == 0:
            log_ok(f"openssl disponible: {resultado.stdout.strip()}")
        else:
            log_fail("openssl no responde correctamente")
    except FileNotFoundError:
        log_fail("openssl no encontrado en el PATH",
                 "instala openssl y asegurate de que esta en el PATH del sistema")
    except Exception as e:
        log_fail("error al ejecutar openssl", str(e))

    # comprobar libreria cryptography de python
    if CRYPTO_OK:
        log_ok("libreria 'cryptography' de python disponible")
    else:
        log_warn("libreria 'cryptography' no instalada -> instalando ahora...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "cryptography"],
                capture_output=True, check=True
            )
            log_ok("libreria 'cryptography' instalada correctamente")
            log_info("reinicia el tester para que surta efecto")
            sys.exit(0)
        except Exception as e:
            log_fail("no se pudo instalar 'cryptography'", str(e))
            log_info("ejecuta manualmente: pip install cryptography")
            sys.exit(1)

    # comprobar acceso a directorio temporal
    try:
        ruta_prueba = os.path.join(DIR_TEMP, "prueba_escritura.tmp")
        with open(ruta_prueba, "w") as f:
            f.write("ok")
        os.remove(ruta_prueba)
        log_ok(f"directorio temporal accesible: {DIR_TEMP}")
    except Exception as e:
        log_fail("no se puede escribir en el directorio temporal", str(e))

# ─────────────────────────────────────────────
# bloque 1: generacion de claves RSA con openssl
# ─────────────────────────────────────────────

RUTA_CLAVE_PRIVADA = os.path.join(DIR_TEMP, "server_key.pem")
RUTA_CERTIFICADO   = os.path.join(DIR_TEMP, "server_cert.pem")

def test_generacion_claves():
    separador("BLOQUE 1 — GENERACION DE CLAVES RSA (openssl)")

    # generar clave privada RSA-2048
    log_info("generando clave privada RSA-2048...")
    try:
        resultado = subprocess.run(
            ["openssl", "genrsa", "-out", RUTA_CLAVE_PRIVADA, str(TAM_CLAVE_RSA)],
            capture_output=True, text=True, timeout=15
        )
        if resultado.returncode == 0 and os.path.exists(RUTA_CLAVE_PRIVADA):
            tamano = os.path.getsize(RUTA_CLAVE_PRIVADA)
            log_ok(f"clave privada generada ({tamano} bytes): {RUTA_CLAVE_PRIVADA}")
        else:
            log_fail("error al generar la clave privada", resultado.stderr.strip())
            return False
    except Exception as e:
        log_fail("excepcion al generar clave privada", str(e))
        return False

    # generar certificado autofirmado (contiene la clave publica)
    log_info("generando certificado autofirmado X.509...")
    try:
        resultado = subprocess.run(
            ["openssl", "req", "-new", "-x509",
             "-key", RUTA_CLAVE_PRIVADA,
             "-out", RUTA_CERTIFICADO,
             "-days", "365",
             "-subj", "/CN=TestServer/O=PracticaAPL02/C=ES"],
            capture_output=True, text=True, timeout=15
        )
        if resultado.returncode == 0 and os.path.exists(RUTA_CERTIFICADO):
            tamano = os.path.getsize(RUTA_CERTIFICADO)
            log_ok(f"certificado generado ({tamano} bytes): {RUTA_CERTIFICADO}")
        else:
            log_fail("error al generar el certificado", resultado.stderr.strip())
            return False
    except Exception as e:
        log_fail("excepcion al generar certificado", str(e))
        return False

    # verificar que el certificado es valido con openssl verify
    try:
        resultado = subprocess.run(
            ["openssl", "verify", "-CAfile", RUTA_CERTIFICADO, RUTA_CERTIFICADO],
            capture_output=True, text=True, timeout=10
        )
        if resultado.returncode == 0:
            log_ok("verificacion del certificado con openssl: OK")
        else:
            log_warn(f"verificacion del certificado: {resultado.stdout.strip()}")
    except Exception as e:
        log_warn(f"no se pudo verificar el certificado: {e}")

    # comprobar que podemos leer la clave publica del certificado
    try:
        resultado = subprocess.run(
            ["openssl", "x509", "-in", RUTA_CERTIFICADO, "-pubkey", "-noout"],
            capture_output=True, text=True, timeout=10
        )
        if resultado.returncode == 0 and "BEGIN PUBLIC KEY" in resultado.stdout:
            log_ok("clave publica extraida del certificado correctamente")
        else:
            log_fail("no se pudo extraer la clave publica del certificado")
    except Exception as e:
        log_fail("error al extraer clave publica", str(e))

    return True

# ─────────────────────────────────────────────
# bloque 2: cifrado y descifrado RSA
# ─────────────────────────────────────────────

# cargamos las claves una sola vez para reutilizarlas
def cargar_clave_publica():
    with open(RUTA_CERTIFICADO, "rb") as f:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert.public_key()

def cargar_clave_privada():
    with open(RUTA_CLAVE_PRIVADA, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def cifrar_con_rsa(clave_publica, datos):
    # cifrado RSA con padding OAEP (el mas seguro para cifrar claves de sesion)
    return clave_publica.encrypt(
        datos,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def descifrar_con_rsa(clave_privada, datos_cifrados):
    # descifrado RSA con el mismo padding OAEP
    return clave_privada.decrypt(
        datos_cifrados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def test_cifrado_rsa():
    separador("BLOQUE 2 — CIFRADO / DESCIFRADO RSA (distribucion de clave)")

    try:
        clave_publica  = cargar_clave_publica()
        clave_privada  = cargar_clave_privada()
        log_ok("claves RSA cargadas desde los ficheros PEM")
    except Exception as e:
        log_fail("no se pudieron cargar las claves RSA", str(e))
        return

    # prueba 1: cifrar y descifrar una clave de sesion AES aleatoria
    clave_sesion_original = os.urandom(TAM_CLAVE_AES)
    try:
        clave_cifrada    = cifrar_con_rsa(clave_publica, clave_sesion_original)
        clave_descifrada = descifrar_con_rsa(clave_privada, clave_cifrada)
        if clave_sesion_original == clave_descifrada:
            log_ok(f"cifrado/descifrado RSA de clave AES-256 ({TAM_CLAVE_AES} bytes): OK")
        else:
            log_fail("la clave descifrada no coincide con la original")
    except Exception as e:
        log_fail("excepcion en cifrado/descifrado RSA", str(e))

    # prueba 2: verificar que la clave cifrada tiene el tamano correcto para RSA-2048
    try:
        clave_cifrada = cifrar_con_rsa(clave_publica, clave_sesion_original)
        tam_esperado  = TAM_CLAVE_RSA // 8  # 2048 bits -> 256 bytes
        if len(clave_cifrada) == tam_esperado:
            log_ok(f"tamano del bloque RSA cifrado: {len(clave_cifrada)} bytes (correcto para RSA-{TAM_CLAVE_RSA})")
        else:
            log_warn(f"tamano inesperado del bloque cifrado: {len(clave_cifrada)} bytes (esperado: {tam_esperado})")
    except Exception as e:
        log_fail("error al verificar tamano del bloque cifrado", str(e))

    # prueba 3: descifrar con clave incorrecta debe fallar
    try:
        clave_privada_falsa = rsa.generate_private_key(
            public_exponent=65537,
            key_size=TAM_CLAVE_RSA,
            backend=default_backend()
        )
        clave_cifrada = cifrar_con_rsa(clave_publica, clave_sesion_original)
        try:
            descifrar_con_rsa(clave_privada_falsa, clave_cifrada)
            log_fail("descifrar con clave incorrecta deberia fallar pero no lo hizo")
        except Exception:
            log_ok("descifrado con clave RSA incorrecta falla correctamente (seguridad OK)")
    except Exception as e:
        log_warn(f"no se pudo probar el descifrado con clave erronea: {e}")

    # prueba 4: cifrar el mismo dato dos veces da resultados distintos (OAEP es probabilistico)
    try:
        cifrado_1 = cifrar_con_rsa(clave_publica, clave_sesion_original)
        cifrado_2 = cifrar_con_rsa(clave_publica, clave_sesion_original)
        if cifrado_1 != cifrado_2:
            log_ok("cifrado RSA-OAEP es probabilistico: dos cifrados del mismo dato son distintos")
        else:
            log_warn("los dos cifrados son identicos, el padding puede no ser aleatorio")
    except Exception as e:
        log_warn(f"no se pudo probar el caracter probabilistico: {e}")

# ─────────────────────────────────────────────
# bloque 3: cifrado y descifrado AES
# ─────────────────────────────────────────────

def cifrar_aes(clave, iv, datos):
    # cifrado AES-256-CBC con padding PKCS7
    from cryptography.hazmat.primitives import padding as sym_padding
    padder  = sym_padding.PKCS7(128).padder()
    datos_p = padder.update(datos) + padder.finalize()
    cifrador = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    enc      = cifrador.encryptor()
    return enc.update(datos_p) + enc.finalize()

def descifrar_aes(clave, iv, datos_cifrados):
    # descifrado AES-256-CBC con quita de padding PKCS7
    from cryptography.hazmat.primitives import padding as sym_padding
    cifrador = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    dec      = cifrador.decryptor()
    datos_p  = dec.update(datos_cifrados) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(datos_p) + unpadder.finalize()

def test_cifrado_aes():
    separador("BLOQUE 3 — CIFRADO / DESCIFRADO AES-256-CBC (cifrado simetrico)")

    clave = os.urandom(TAM_CLAVE_AES)
    iv    = os.urandom(TAM_IV)

    # prueba 1: texto simple
    datos_originales = b"hola esto es un mensaje de prueba para AES-256-CBC"
    try:
        cifrado    = cifrar_aes(clave, iv, datos_originales)
        descifrado = descifrar_aes(clave, iv, cifrado)
        if descifrado == datos_originales:
            log_ok("cifrado/descifrado AES de texto simple: OK")
        else:
            log_fail("el texto descifrado no coincide con el original")
    except Exception as e:
        log_fail("excepcion en cifrado/descifrado AES basico", str(e))

    # prueba 2: fichero de texto pequeño (1 KB)
    datos_1kb = os.urandom(1024)
    try:
        cifrado    = cifrar_aes(clave, iv, datos_1kb)
        descifrado = descifrar_aes(clave, iv, cifrado)
        if descifrado == datos_1kb:
            log_ok("cifrado/descifrado AES con 1 KB de datos binarios: OK")
        else:
            log_fail("los datos de 1 KB no coinciden tras descifrar")
    except Exception as e:
        log_fail("excepcion con datos de 1 KB", str(e))

    # prueba 3: fichero mediano (100 KB)
    datos_100kb = os.urandom(100 * 1024)
    try:
        t_ini      = time.time()
        cifrado    = cifrar_aes(clave, iv, datos_100kb)
        descifrado = descifrar_aes(clave, iv, cifrado)
        t_fin      = time.time()
        if descifrado == datos_100kb:
            log_ok(f"cifrado/descifrado AES con 100 KB: OK ({(t_fin-t_ini)*1000:.1f} ms)")
        else:
            log_fail("los datos de 100 KB no coinciden tras descifrar")
    except Exception as e:
        log_fail("excepcion con datos de 100 KB", str(e))

    # prueba 4: fichero grande (5 MB)
    datos_5mb = os.urandom(5 * 1024 * 1024)
    try:
        t_ini      = time.time()
        cifrado    = cifrar_aes(clave, iv, datos_5mb)
        descifrado = descifrar_aes(clave, iv, cifrado)
        t_fin      = time.time()
        if descifrado == datos_5mb:
            log_ok(f"cifrado/descifrado AES con 5 MB: OK ({(t_fin-t_ini)*1000:.0f} ms)")
        else:
            log_fail("los datos de 5 MB no coinciden tras descifrar")
    except Exception as e:
        log_fail("excepcion con datos de 5 MB", str(e))

    # prueba 5: descifrar con clave incorrecta produce datos basura (no excepcion PKCS7 siempre)
    try:
        clave_mala = os.urandom(TAM_CLAVE_AES)
        datos      = os.urandom(64)
        cifrado    = cifrar_aes(clave, iv, datos)
        try:
            descifrado_malo = descifrar_aes(clave_mala, iv, cifrado)
            if descifrado_malo != datos:
                log_ok("descifrado AES con clave incorrecta produce datos distintos (correcto)")
            else:
                log_fail("descifrado con clave incorrecta produjo el dato original (error grave)")
        except Exception:
            log_ok("descifrado AES con clave incorrecta falla con excepcion (correcto, padding invalido)")
    except Exception as e:
        log_warn(f"no se pudo probar descifrado con clave erronea: {e}")

    # prueba 6: integridad por hash SHA-256
    try:
        datos      = os.urandom(2048)
        hash_orig  = hashlib.sha256(datos).hexdigest()
        cifrado    = cifrar_aes(clave, iv, datos)
        descifrado = descifrar_aes(clave, iv, cifrado)
        hash_desc  = hashlib.sha256(descifrado).hexdigest()
        if hash_orig == hash_desc:
            log_ok(f"integridad SHA-256 tras cifrado/descifrado AES: OK")
        else:
            log_fail("el hash SHA-256 no coincide: datos corrompidos")
    except Exception as e:
        log_fail("excepcion en prueba de integridad SHA-256", str(e))

# ─────────────────────────────────────────────
# bloque 4: estructura de metadatos
# ─────────────────────────────────────────────

# formato del struct MetadatosFichero en C (debe coincidir exactamente con common.h):
# uint64_t  longitud_fichero      -> Q (8 bytes)
# char      nombre_fichero[256]   -> 256s
# char      fecha_hora[20]        -> 20s
# uint8_t   clave_sesion_cifrada[256] -> 256s
# uint8_t   iv[16]                -> 16s
# int       len_clave_cifrada     -> i (4 bytes)
# total: 8 + 256 + 20 + 256 + 16 + 4 = 560 bytes
FORMATO_META  = "Q256s20s256s16si"
TAM_META      = struct.calcsize(FORMATO_META)

def empaquetar_meta(longitud, nombre, fecha_hora, clave_cifrada, iv, len_clave):
    # convierte los campos a bytes con el formato correcto para enviar por socket
    return struct.pack(
        FORMATO_META,
        longitud,
        nombre.encode("utf-8")[:255].ljust(256, b'\x00'),
        fecha_hora.encode("utf-8")[:19].ljust(20, b'\x00'),
        clave_cifrada.ljust(256, b'\x00'),
        iv,
        len_clave
    )

def desempaquetar_meta(datos_brutos):
    # extrae los campos del buffer recibido por socket
    longitud, nombre_b, fecha_b, clave_cifrada_b, iv_b, len_clave = struct.unpack(
        FORMATO_META, datos_brutos
    )
    nombre    = nombre_b.rstrip(b'\x00').decode("utf-8", errors="replace")
    fecha     = fecha_b.rstrip(b'\x00').decode("utf-8", errors="replace")
    return longitud, nombre, fecha, clave_cifrada_b, iv_b, len_clave

def test_estructura_metadatos():
    separador("BLOQUE 4 — ESTRUCTURA DE METADATOS (serializacion)")

    # verificar tamano del struct
    tam_esperado = 560  # 8+256+20+256+16+4
    if TAM_META == tam_esperado:
        log_ok(f"tamano del struct MetadatosFichero: {TAM_META} bytes (correcto)")
    else:
        log_warn(f"tamano del struct: {TAM_META} bytes (esperado aprox {tam_esperado}, puede variar por alineacion)")

    # prueba 1: empaquetar y desempaquetar un struct completo
    try:
        longitud_orig  = 123456
        nombre_orig    = "fichero_prueba.txt"
        fecha_orig     = "2025-05-20 12:30:00"
        clave_c_orig   = os.urandom(256)
        iv_orig        = os.urandom(TAM_IV)
        len_clave_orig = 256

        raw = empaquetar_meta(longitud_orig, nombre_orig, fecha_orig,
                              clave_c_orig, iv_orig, len_clave_orig)

        longitud_r, nombre_r, fecha_r, clave_c_r, iv_r, len_clave_r = desempaquetar_meta(raw)

        errores = []
        if longitud_r  != longitud_orig:  errores.append("longitud_fichero")
        if nombre_r    != nombre_orig:    errores.append("nombre_fichero")
        if fecha_r     != fecha_orig:     errores.append("fecha_hora")
        if clave_c_r[:256] != clave_c_orig: errores.append("clave_sesion_cifrada")
        if iv_r        != iv_orig:        errores.append("iv")
        if len_clave_r != len_clave_orig: errores.append("len_clave_cifrada")

        if not errores:
            log_ok("serializacion/deserializacion de MetadatosFichero: todos los campos OK")
        else:
            log_fail(f"campos con error: {', '.join(errores)}")
    except Exception as e:
        log_fail("excepcion al serializar/deserializar metadatos", str(e))

    # prueba 2: nombre con caracteres especiales (ruta de windows)
    try:
        nombre_esp = "mi_fichero (v2).bin"
        raw = empaquetar_meta(0, nombre_esp, "2025-01-01 00:00:00",
                              bytes(256), bytes(TAM_IV), 0)
        _, nombre_r, _, _, _, _ = desempaquetar_meta(raw)
        if nombre_r == nombre_esp:
            log_ok("nombre de fichero con espacios y parentesis: OK")
        else:
            log_fail(f"nombre con caracteres especiales no se preserva: '{nombre_r}'")
    except Exception as e:
        log_fail("excepcion con nombre especial", str(e))

    # prueba 3: longitud de fichero maxima (uint64)
    try:
        longitud_max = 2**64 - 1
        raw = empaquetar_meta(longitud_max, "test.bin", "2025-01-01 00:00:00",
                              bytes(256), bytes(TAM_IV), 256)
        longitud_r, _, _, _, _, _ = desempaquetar_meta(raw)
        if longitud_r == longitud_max:
            log_ok(f"longitud_fichero uint64 maximo ({longitud_max}): OK")
        else:
            log_fail("overflow en longitud_fichero uint64")
    except Exception as e:
        log_fail("excepcion con longitud uint64 maxima", str(e))

# ─────────────────────────────────────────────
# bloque 5: prueba de conexion TCP
# ─────────────────────────────────────────────

def test_conexion_tcp():
    separador("BLOQUE 5 — CONEXION TCP (socket basico)")

    # prueba 1: crear un servidor de echo simple y conectar un cliente
    resultado_echo = {"recibido": None, "error": None}

    def servidor_echo():
        # servidor minimo que acepta una conexion, lee datos y los devuelve
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", PUERTO_TEST))
            srv.listen(1)
            srv.settimeout(TIMEOUT_SOCKET)
            conn, _ = srv.accept()
            datos = conn.recv(1024)
            conn.send(datos)  # echo
            conn.close()
            srv.close()
            resultado_echo["recibido"] = datos
        except Exception as e:
            resultado_echo["error"] = str(e)

    hilo_srv = threading.Thread(target=servidor_echo, daemon=True)
    hilo_srv.start()
    time.sleep(0.2)  # dar tiempo al servidor a arrancar

    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.settimeout(TIMEOUT_SOCKET)
        cli.connect(("127.0.0.1", PUERTO_TEST))
        mensaje = b"test_conexion_tcp_ok"
        cli.send(mensaje)
        respuesta = cli.recv(1024)
        cli.close()
        hilo_srv.join(timeout=3)

        if respuesta == mensaje:
            log_ok("conexion TCP cliente-servidor en loopback: OK")
        else:
            log_fail("el servidor echo no devolvio el mismo mensaje")
    except Exception as e:
        log_fail("error en prueba de conexion TCP basica", str(e))

    # prueba 2: conectar a un puerto cerrado debe fallar
    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.settimeout(2)
        try:
            cli.connect(("127.0.0.1", PUERTO_TEST + 1))
            log_fail("la conexion a un puerto cerrado no deberia funcionar")
        except (ConnectionRefusedError, socket.timeout, OSError):
            log_ok("conexion a puerto cerrado falla correctamente")
        finally:
            cli.close()
    except Exception as e:
        log_warn(f"prueba de puerto cerrado: {e}")

# ─────────────────────────────────────────────
# bloque 6: flujo completo de transferencia
# ─────────────────────────────────────────────

def servidor_transferencia(puerto, ruta_clave_privada, resultado):
    # simula el servidor de la practica: recibe metadatos + fichero cifrado, descifra y guarda
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", puerto))
        srv.listen(1)
        srv.settimeout(10)
        conn, _ = srv.accept()
        conn.settimeout(10)

        # 1. recibir metadatos
        datos_meta = b""
        while len(datos_meta) < TAM_META:
            chunk = conn.recv(TAM_META - len(datos_meta))
            if not chunk:
                break
            datos_meta += chunk

        longitud, nombre, fecha, clave_cifrada, iv, len_clave = desempaquetar_meta(datos_meta)

        # 2. descifrar la clave de sesion con la clave privada RSA
        clave_privada  = cargar_clave_privada()
        clave_sesion   = descifrar_con_rsa(clave_privada, clave_cifrada[:len_clave])

        # 3. enviar aceptacion (int = 1)
        conn.send(struct.pack("i", 1))

        # 4. recibir el fichero cifrado completo
        # el tamano cifrado puede ser mayor que el original (padding AES)
        tam_cifrado = struct.unpack("Q", conn.recv(8))[0]
        datos_cifrados = b""
        while len(datos_cifrados) < tam_cifrado:
            chunk = conn.recv(min(4096, tam_cifrado - len(datos_cifrados)))
            if not chunk:
                break
            datos_cifrados += chunk

        # 5. descifrar el fichero
        datos_descifrados = descifrar_aes(clave_sesion, iv, datos_cifrados)

        conn.close()
        srv.close()

        resultado["longitud"]    = longitud
        resultado["nombre"]      = nombre
        resultado["fecha"]       = fecha
        resultado["datos"]       = datos_descifrados
        resultado["ok"]          = True

    except Exception as e:
        resultado["ok"]    = False
        resultado["error"] = str(e)

def cliente_transferencia(puerto, ruta_cert, fichero_bytes, nombre_fichero):
    # simula el cliente de la practica: envia metadatos + fichero cifrado
    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.settimeout(10)
        cli.connect(("127.0.0.1", puerto))

        # 1. generar clave de sesion e IV aleatorios
        clave_sesion = os.urandom(TAM_CLAVE_AES)
        iv           = os.urandom(TAM_IV)

        # 2. cifrar la clave de sesion con la clave publica RSA del servidor
        clave_publica  = cargar_clave_publica()
        clave_cifrada  = cifrar_con_rsa(clave_publica, clave_sesion)
        len_clave      = len(clave_cifrada)

        # 3. construir y enviar los metadatos
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        raw_meta = empaquetar_meta(
            len(fichero_bytes), nombre_fichero, fecha,
            clave_cifrada, iv, len_clave
        )
        cli.send(raw_meta)

        # 4. esperar aceptacion del servidor
        respuesta = struct.unpack("i", cli.recv(4))[0]
        if respuesta != 1:
            cli.close()
            return False

        # 5. cifrar el fichero y enviarlo
        datos_cifrados = cifrar_aes(clave_sesion, iv, fichero_bytes)
        # primero enviamos el tamano del bloque cifrado (8 bytes)
        cli.send(struct.pack("Q", len(datos_cifrados)))
        # luego enviamos los datos cifrados
        cli.sendall(datos_cifrados)

        cli.close()
        return True

    except Exception as e:
        return False

def test_flujo_completo(nombre_test, datos_fichero, puerto):
    # ejecuta servidor y cliente en paralelo y verifica el resultado
    resultado_srv = {}

    hilo_srv = threading.Thread(
        target=servidor_transferencia,
        args=(puerto, RUTA_CLAVE_PRIVADA, resultado_srv),
        daemon=True
    )
    hilo_srv.start()
    time.sleep(0.3)

    exito_cli = cliente_transferencia(puerto, RUTA_CERTIFICADO, datos_fichero, "prueba.bin")
    hilo_srv.join(timeout=15)

    if not exito_cli:
        log_fail(f"{nombre_test}: el cliente fallo al enviar")
        return

    if not resultado_srv.get("ok"):
        log_fail(f"{nombre_test}: el servidor fallo", resultado_srv.get("error", "error desconocido"))
        return

    datos_recv = resultado_srv.get("datos", b"")
    if datos_recv == datos_fichero:
        tam_kb = len(datos_fichero) / 1024
        log_ok(f"{nombre_test} ({tam_kb:.1f} KB): datos originales == datos recibidos y descifrados")
    else:
        log_fail(
            f"{nombre_test}: los datos no coinciden",
            f"enviados={len(datos_fichero)} bytes, recibidos={len(datos_recv)} bytes"
        )

def test_transferencia_completa():
    separador("BLOQUE 6 — FLUJO COMPLETO DE TRANSFERENCIA CIFRADA")

    # prueba con fichero de texto pequeño
    test_flujo_completo(
        "fichero texto 512 B",
        b"Este es un fichero de texto de prueba. " * 13,
        PUERTO_TEST + 10
    )
    time.sleep(0.5)

    # prueba con datos binarios de 10 KB
    test_flujo_completo(
        "datos binarios 10 KB",
        os.urandom(10 * 1024),
        PUERTO_TEST + 11
    )
    time.sleep(0.5)

    # prueba con datos binarios de 500 KB
    test_flujo_completo(
        "datos binarios 500 KB",
        os.urandom(500 * 1024),
        PUERTO_TEST + 12
    )
    time.sleep(0.5)

    # prueba con fichero de 2 MB
    test_flujo_completo(
        "datos binarios 2 MB",
        os.urandom(2 * 1024 * 1024),
        PUERTO_TEST + 13
    )
    time.sleep(0.5)

    # prueba con fichero de exactamente 16 bytes (un solo bloque AES)
    test_flujo_completo(
        "exactamente 1 bloque AES (16 B)",
        os.urandom(16),
        PUERTO_TEST + 14
    )
    time.sleep(0.5)

    # prueba con fichero de 1 byte (caso extremo de padding)
    test_flujo_completo(
        "fichero de 1 byte (padding extremo)",
        os.urandom(1),
        PUERTO_TEST + 15
    )
    time.sleep(0.5)

    # prueba con fichero de ceros (caso degenrado)
    test_flujo_completo(
        "fichero relleno de ceros 1 KB",
        bytes(1024),
        PUERTO_TEST + 16
    )

# ─────────────────────────────────────────────
# bloque 7: integridad end-to-end con hash
# ─────────────────────────────────────────────

def test_integridad_hash():
    separador("BLOQUE 7 — INTEGRIDAD END-TO-END (SHA-256)")

    for tamano_kb, puerto in [(4, PUERTO_TEST + 20), (128, PUERTO_TEST + 21)]:
        datos_originales = os.urandom(tamano_kb * 1024)
        hash_original    = hashlib.sha256(datos_originales).hexdigest()

        resultado_srv = {}
        hilo_srv = threading.Thread(
            target=servidor_transferencia,
            args=(puerto, RUTA_CLAVE_PRIVADA, resultado_srv),
            daemon=True
        )
        hilo_srv.start()
        time.sleep(0.3)

        cliente_transferencia(puerto, RUTA_CERTIFICADO, datos_originales, "hash_test.bin")
        hilo_srv.join(timeout=15)

        if resultado_srv.get("ok"):
            hash_recibido = hashlib.sha256(resultado_srv["datos"]).hexdigest()
            if hash_original == hash_recibido:
                log_ok(f"integridad SHA-256 con {tamano_kb} KB: hashes identicos")
            else:
                log_fail(f"integridad SHA-256 con {tamano_kb} KB: hashes distintos",
                         f"orig={hash_original[:16]}... recv={hash_recibido[:16]}...")
        else:
            log_fail(f"prueba de hash con {tamano_kb} KB fallo en el servidor",
                     resultado_srv.get("error", ""))
        time.sleep(0.5)

# ─────────────────────────────────────────────
# bloque 8: servidor iterativo (multiples clientes secuenciales)
# ─────────────────────────────────────────────

def servidor_iterativo(puerto, ruta_clave_privada, num_clientes, resultados):
    # servidor iterativo: atiende num_clientes conexiones una tras otra
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", puerto))
        srv.listen(5)
        srv.settimeout(15)

        clave_privada = cargar_clave_privada()

        for i in range(num_clientes):
            conn, _ = srv.accept()
            conn.settimeout(10)

            # recibir metadatos
            datos_meta = b""
            while len(datos_meta) < TAM_META:
                chunk = conn.recv(TAM_META - len(datos_meta))
                if not chunk:
                    break
                datos_meta += chunk

            longitud, nombre, fecha, clave_cifrada, iv, len_clave = desempaquetar_meta(datos_meta)
            clave_sesion = descifrar_con_rsa(clave_privada, clave_cifrada[:len_clave])
            conn.send(struct.pack("i", 1))

            tam_cifrado = struct.unpack("Q", conn.recv(8))[0]
            datos_cifrados = b""
            while len(datos_cifrados) < tam_cifrado:
                chunk = conn.recv(min(4096, tam_cifrado - len(datos_cifrados)))
                if not chunk:
                    break
                datos_cifrados += chunk

            datos_desc = descifrar_aes(clave_sesion, iv, datos_cifrados)
            resultados.append(datos_desc)
            conn.close()

        srv.close()
    except Exception as e:
        resultados.append(None)

def test_servidor_iterativo():
    separador("BLOQUE 8 — SERVIDOR ITERATIVO (multiples clientes secuenciales)")

    num_clientes   = 3
    puerto         = PUERTO_TEST + 30
    datos_clientes = [os.urandom(random.randint(512, 4096)) for _ in range(num_clientes)]
    resultados_srv = []

    hilo_srv = threading.Thread(
        target=servidor_iterativo,
        args=(puerto, RUTA_CLAVE_PRIVADA, num_clientes, resultados_srv),
        daemon=True
    )
    hilo_srv.start()
    time.sleep(0.3)

    # los clientes se conectan uno tras otro (iterativo)
    exitos = 0
    for i, datos in enumerate(datos_clientes):
        time.sleep(0.1)
        if cliente_transferencia(puerto, RUTA_CERTIFICADO, datos, f"cliente_{i}.bin"):
            exitos += 1

    hilo_srv.join(timeout=20)

    if len(resultados_srv) == num_clientes:
        correctos = sum(
            1 for orig, recv in zip(datos_clientes, resultados_srv)
            if recv is not None and orig == recv
        )
        if correctos == num_clientes:
            log_ok(f"servidor iterativo: {num_clientes} clientes atendidos correctamente")
        else:
            log_fail(f"servidor iterativo: solo {correctos}/{num_clientes} transferencias correctas")
    else:
        log_fail(f"servidor iterativo: se esperaban {num_clientes} resultados, se obtuvieron {len(resultados_srv)}")

# ─────────────────────────────────────────────
# resumen final
# ─────────────────────────────────────────────

def resumen_final():
    total = ok + fail
    print(f"\n{negrita(cyan('═' * 55))}")
    print(f"  {negrita('RESUMEN FINAL')}")
    print(f"{negrita(cyan('═' * 55))}")
    print(f"  total de pruebas: {total}")
    print(f"  {verde(f'correctas: {ok}')}")
    if fail > 0:
        print(f"  {rojo(f'fallidas:  {fail}')}")
    else:
        print(f"  fallidas:  {fail}")
    if warns > 0:
        print(f"  {amarillo(f'avisos:    {warns}')}")

    print()
    if fail == 0:
        print(f"  {verde(negrita('todo correcto - la logica de la practica funciona'))}")
    elif fail <= 3:
        print(f"  {amarillo(negrita('hay algunos fallos menores que revisar'))}")
    else:
        print(f"  {rojo(negrita('hay fallos importantes - revisa los bloques marcados'))}")

    print(f"\n  directorio temporal de prueba: {DIR_TEMP}")
    print(f"  (puedes borrarlo cuando quieras)\n")

# ─────────────────────────────────────────────
# punto de entrada
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{negrita(cyan('╔' + '═'*53 + '╗'))}")
    print(f"{negrita(cyan('║'))}  TESTER APL02 - TRANSFERENCIA FICHEROS CIFRADA    {negrita(cyan('║'))}")
    print(f"{negrita(cyan('║'))}  Ingenieria de Protocolos de Comunicaciones       {negrita(cyan('║'))}")
    print(f"{negrita(cyan('╚' + '═'*53 + '╝'))}\n")
    print(f"  inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        test_entorno()
        claves_ok = test_generacion_claves()

        if claves_ok and CRYPTO_OK:
            test_cifrado_rsa()
            test_cifrado_aes()
            test_estructura_metadatos()
            test_conexion_tcp()
            test_transferencia_completa()
            test_integridad_hash()
            test_servidor_iterativo()
        else:
            log_fail("se omiten los bloques siguientes por fallo en generacion de claves o libreria crypto")

    except KeyboardInterrupt:
        print(f"\n  {amarillo('pruebas interrumpidas por el usuario')}")
    finally:
        # limpiar el directorio temporal
        try:
            shutil.rmtree(DIR_TEMP)
        except Exception:
            pass
        resumen_final()