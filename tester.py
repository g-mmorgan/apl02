# tester exhaustivo para la practica APL02
# hace todo automaticamente:
#   - instala dependencias python si faltan
#   - genera claves RSA con openssl
#   - compila servidor.exe y cliente.exe con gcc
#   - prueba cifrado RSA, AES, serializacion, TCP y flujo completo
#   - prueba los ejecutables reales con un fichero de verdad
#
# requisitos: python 3.x, openssl en PATH, gcc en PATH
# ejecutar:   python tester.py

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

PUERTO_TEST    = 9999
TAM_CLAVE_AES  = 32
TAM_IV         = 16
TAM_CLAVE_RSA  = 2048
MAX_NOMBRE     = 256
TIMEOUT_SOCKET = 5

OPENSSL_DIR = r"C:\OpenSSL-Win64"
OPENSSL_INC = os.path.join(OPENSSL_DIR, "include")
OPENSSL_LIB = os.path.join(OPENSSL_DIR, "lib")

ok    = 0
fail  = 0
warns = 0

DIR_TEMP = tempfile.mkdtemp(prefix="tester_apl02_")

RUTA_CLAVE_PRIVADA = os.path.join(DIR_TEMP, "server_key.pem")
RUTA_CERTIFICADO   = os.path.join(DIR_TEMP, "server_cert.pem")

# ─────────────────────────────────────────────
# colores y log
# compatible con Python 3.8: sin comillas anidadas en f-strings
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
        print("         " + rojo("->") + " " + detalle)

def log_warn(msg):
    global warns
    warns += 1
    print("  " + amarillo("[WARN]") + " " + msg)

def log_info(msg):
    print("  " + cyan("[INFO]") + " " + msg)

def separador(titulo):
    linea = cyan("=" * 60)
    print("\n" + negrita(linea))
    print("  " + negrita(titulo))
    print(negrita(linea))

# ─────────────────────────────────────────────
# bloque 0: entorno
# ─────────────────────────────────────────────

def test_entorno():
    separador("BLOQUE 0 - COMPROBACION DEL ENTORNO")

    v = sys.version_info
    if v.major >= 3 and v.minor >= 6:
        log_ok("python " + str(v.major) + "." + str(v.minor) + "." + str(v.micro))
    else:
        log_fail("se necesita python 3.6+", sys.version)

    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log_ok("openssl: " + r.stdout.strip())
        else:
            log_fail("openssl no responde")
    except FileNotFoundError:
        log_fail("openssl no encontrado en PATH")

    try:
        r = subprocess.run(["gcc", "--version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log_ok("gcc: " + r.stdout.splitlines()[0].strip())
        else:
            log_fail("gcc no responde")
    except FileNotFoundError:
        log_fail("gcc no encontrado en PATH", "instala MinGW y anyadelo al PATH del sistema")

    if os.path.isdir(OPENSSL_INC):
        log_ok("directorio include de OpenSSL encontrado: " + OPENSSL_INC)
    else:
        log_warn("no se encuentra " + OPENSSL_INC + " -> la compilacion puede fallar")

    if os.path.isdir(OPENSSL_LIB):
        log_ok("directorio lib de OpenSSL encontrado: " + OPENSSL_LIB)
    else:
        log_warn("no se encuentra " + OPENSSL_LIB + " -> la compilacion puede fallar")

    global CRYPTO_OK
    if CRYPTO_OK:
        log_ok("libreria python 'cryptography' disponible")
    else:
        log_info("instalando libreria 'cryptography'...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "cryptography"],
                capture_output=True, check=True
            )
            log_ok("libreria 'cryptography' instalada")
            log_info("reinicia el tester para que surta efecto")
            sys.exit(0)
        except Exception as e:
            log_fail("no se pudo instalar 'cryptography'", str(e))
            sys.exit(1)

    try:
        ruta = os.path.join(DIR_TEMP, "test.tmp")
        open(ruta, "w").close()
        os.remove(ruta)
        log_ok("directorio temporal OK: " + DIR_TEMP)
    except Exception as e:
        log_fail("no se puede escribir en directorio temporal", str(e))

# ─────────────────────────────────────────────
# bloque 1: generacion de claves RSA
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
            log_ok("clave privada RSA-2048 generada (" + str(os.path.getsize(RUTA_CLAVE_PRIVADA)) + " bytes)")
        else:
            log_fail("error al generar clave privada", r.stderr.strip())
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
            log_ok("certificado X.509 generado (" + str(os.path.getsize(RUTA_CERTIFICADO)) + " bytes)")
        else:
            log_fail("error al generar el certificado", r.stderr.strip())
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
            log_warn("openssl verify: " + r.stdout.strip())
    except Exception as e:
        log_warn("no se pudo verificar el certificado: " + str(e))

    try:
        r = subprocess.run(
            ["openssl", "x509", "-in", RUTA_CERTIFICADO, "-pubkey", "-noout"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and "BEGIN PUBLIC KEY" in r.stdout:
            log_ok("clave publica extraida del certificado: OK")
        else:
            log_fail("no se pudo extraer la clave publica")
    except Exception as e:
        log_fail("error extrayendo clave publica", str(e))

    return True

# ─────────────────────────────────────────────
# bloque 2: compilacion con gcc
# ─────────────────────────────────────────────

DIR_PROYECTO = os.path.dirname(os.path.abspath(__file__))

RUTA_SERVIDOR_EXE = os.path.join(DIR_TEMP, "servidor.exe")
RUTA_CLIENTE_EXE  = os.path.join(DIR_TEMP, "cliente.exe")

def test_compilacion():
    separador("BLOQUE 2 - COMPILACION CON GCC")

    fuentes_necesarias = ["common.h", "crypto_utils.h",
                          "crypto_utils.c", "servidor.c", "cliente.c"]
    todos_presentes = True
    for f in fuentes_necesarias:
        ruta = os.path.join(DIR_PROYECTO, f)
        if os.path.isfile(ruta):
            log_ok("fuente encontrado: " + f)
        else:
            log_fail("fuente NO encontrado: " + f, "debe estar en " + DIR_PROYECTO)
            todos_presentes = False

    if not todos_presentes:
        log_warn("compilacion omitida por ficheros fuente faltantes")
        return False

    # flags para MinGW + OpenSSL 1.1.1 en Windows
    # -lgdi32 y -lcrypt32 son necesarios para OpenSSL en Windows
    flags_comunes = [
        "-I" + OPENSSL_INC,
        "-L" + OPENSSL_LIB,
        "-lws2_32", "-lssl", "-lcrypto", "-lgdi32", "-lcrypt32",
        "-Wall",
    ]

    fuente_crypto = os.path.join(DIR_PROYECTO, "crypto_utils.c")

    def compilar(nombre_exe, fuente_principal, ruta_salida):
        log_info("compilando " + nombre_exe + "...")
        cmd = ["gcc", fuente_principal, fuente_crypto, "-o", ruta_salida] + flags_comunes
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=60, cwd=DIR_PROYECTO)
            exe_ok = r.returncode == 0 and os.path.isfile(ruta_salida)
            if exe_ok:
                tam = os.path.getsize(ruta_salida)
                log_ok(nombre_exe + " compilado (" + str(tam // 1024) + " KB)")
                if r.stderr and "warning" in r.stderr.lower():
                    for linea in r.stderr.splitlines():
                        if "warning" in linea.lower():
                            log_warn("gcc warning en " + nombre_exe + ": " + linea.strip()[:120])
                return True
            else:
                salida = (r.stderr or r.stdout).strip()
                # mostrar todas las lineas con "error" para ver el problema completo
                errores = [l for l in salida.splitlines() if "error" in l.lower()]
                if errores:
                    detalle = "\n         ".join(errores[:10])
                else:
                    # si no hay lineas con "error" mostrar todo el output
                    detalle = salida[:2000]
                log_fail("error al compilar " + nombre_exe, detalle)
                return False
        except Exception as e:
            log_fail("excepcion compilando " + nombre_exe, str(e))
            return False

    fuente_srv = os.path.join(DIR_PROYECTO, "servidor.c")
    ok_srv = compilar("servidor.exe", fuente_srv, RUTA_SERVIDOR_EXE)

    fuente_cli = os.path.join(DIR_PROYECTO, "cliente.c")
    ok_cli = compilar("cliente.exe", fuente_cli, RUTA_CLIENTE_EXE)

    if not ok_srv or not ok_cli:
        return False

    return True

# ─────────────────────────────────────────────
# bloque 3: cifrado RSA
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
    return pub.encrypt(datos, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

def descifrar_con_rsa(priv, datos_cifrados):
    return priv.decrypt(datos_cifrados, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

def test_cifrado_rsa():
    separador("BLOQUE 3 - CIFRADO / DESCIFRADO RSA")

    try:
        pub  = cargar_clave_publica()
        priv = cargar_clave_privada()
        log_ok("claves RSA cargadas desde PEM")
    except Exception as e:
        log_fail("no se pudieron cargar las claves", str(e))
        return

    clave = os.urandom(TAM_CLAVE_AES)

    try:
        cifrado    = cifrar_con_rsa(pub, clave)
        descifrado = descifrar_con_rsa(priv, cifrado)
        if descifrado == clave:
            log_ok("cifrado/descifrado RSA-OAEP de clave AES-256 (" + str(TAM_CLAVE_AES) + " B): OK")
        else:
            log_fail("la clave descifrada no coincide con la original")
    except Exception as e:
        log_fail("excepcion en cifrado/descifrado RSA", str(e))

    try:
        cifrado = cifrar_con_rsa(pub, clave)
        if len(cifrado) == TAM_CLAVE_RSA // 8:
            log_ok("tamano bloque RSA cifrado: " + str(len(cifrado)) + " bytes (correcto RSA-" + str(TAM_CLAVE_RSA) + ")")
        else:
            log_warn("tamano inesperado: " + str(len(cifrado)) + " bytes")
    except Exception as e:
        log_fail("error verificando tamano", str(e))

    try:
        priv_falsa = rsa.generate_private_key(65537, TAM_CLAVE_RSA, default_backend())
        cifrado    = cifrar_con_rsa(pub, clave)
        try:
            descifrar_con_rsa(priv_falsa, cifrado)
            log_fail("descifrado con clave incorrecta no fallo (problema de seguridad)")
        except Exception:
            log_ok("descifrado con clave RSA incorrecta falla correctamente")
    except Exception as e:
        log_warn("no se pudo probar clave incorrecta: " + str(e))

    try:
        c1 = cifrar_con_rsa(pub, clave)
        c2 = cifrar_con_rsa(pub, clave)
        if c1 != c2:
            log_ok("RSA-OAEP es probabilistico: dos cifrados del mismo dato son distintos")
        else:
            log_warn("los dos cifrados son identicos (padding puede no ser aleatorio)")
    except Exception as e:
        log_warn("no se pudo probar caracter probabilistico: " + str(e))

# ─────────────────────────────────────────────
# bloque 4: cifrado AES
# ─────────────────────────────────────────────

def cifrar_aes(clave, iv, datos):
    from cryptography.hazmat.primitives import padding as sp
    padder  = sp.PKCS7(128).padder()
    datos_p = padder.update(datos) + padder.finalize()
    enc = Cipher(algorithms.AES(clave), modes.CBC(iv),
                 backend=default_backend()).encryptor()
    return enc.update(datos_p) + enc.finalize()

def descifrar_aes(clave, iv, cifrado):
    from cryptography.hazmat.primitives import padding as sp
    dec    = Cipher(algorithms.AES(clave), modes.CBC(iv),
                    backend=default_backend()).decryptor()
    datos_p = dec.update(cifrado) + dec.finalize()
    unpad   = sp.PKCS7(128).unpadder()
    return unpad.update(datos_p) + unpad.finalize()

def test_cifrado_aes():
    separador("BLOQUE 4 - CIFRADO / DESCIFRADO AES-256-CBC")

    clave = os.urandom(TAM_CLAVE_AES)
    iv    = os.urandom(TAM_IV)

    casos = [
        ("texto simple 50 B",   b"hola esto es una prueba de AES-256-CBC en la practica"),
        ("binario 1 KB",        os.urandom(1024)),
        ("binario 100 KB",      os.urandom(100 * 1024)),
        ("binario 5 MB",        os.urandom(5 * 1024 * 1024)),
        ("exactamente 16 B",    os.urandom(16)),
        ("1 byte",              os.urandom(1)),
        ("ceros 1 KB",          bytes(1024)),
    ]

    for nombre, datos in casos:
        try:
            t0  = time.time()
            enc = cifrar_aes(clave, iv, datos)
            dec = descifrar_aes(clave, iv, enc)
            ms  = (time.time() - t0) * 1000
            if dec == datos:
                log_ok("AES " + nombre + ": OK (" + str(round(ms, 1)) + " ms)")
            else:
                log_fail("AES " + nombre + ": datos no coinciden tras descifrar")
        except Exception as e:
            log_fail("AES " + nombre + ": excepcion", str(e))

    try:
        datos  = os.urandom(4096)
        h_orig = hashlib.sha256(datos).hexdigest()
        h_desc = hashlib.sha256(descifrar_aes(clave, iv, cifrar_aes(clave, iv, datos))).hexdigest()
        if h_orig == h_desc:
            log_ok("integridad SHA-256 tras cifrado/descifrado AES: OK")
        else:
            log_fail("hash SHA-256 no coincide: datos corrompidos")
    except Exception as e:
        log_fail("excepcion en prueba SHA-256", str(e))

# ─────────────────────────────────────────────
# bloque 5: estructura de metadatos
# ─────────────────────────────────────────────

# formato debe coincidir EXACTAMENTE con common.h:
#   uint64_t  longitud_fichero          ->  Q  (8 B)
#   char      nombre_fichero[256]       -> 256s
#   char      fecha_hora[20]            ->  20s
#   uint8_t   clave_sesion_cifrada[256] -> 256s
#   uint8_t   iv[16]                    ->  16s
#   int       len_clave_cifrada         ->  i  (4 B)
#   TOTAL = 560 bytes
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
    separador("BLOQUE 5 - ESTRUCTURA DE METADATOS")

    if TAM_META == 560:
        log_ok("tamano struct MetadatosFichero: " + str(TAM_META) + " bytes (correcto)")
    else:
        log_warn("tamano struct: " + str(TAM_META) + " bytes (esperado 560)")

    try:
        lon_o  = 123456
        nom_o  = "fichero_prueba.txt"
        fec_o  = "2025-05-20 12:30:00"
        cc_o   = os.urandom(256)
        iv_o   = os.urandom(TAM_IV)
        lc_o   = 256
        raw    = empaquetar_meta(lon_o, nom_o, fec_o, cc_o, iv_o, lc_o)
        lon_r, nom_r, fec_r, cc_r, iv_r, lc_r = desempaquetar_meta(raw)
        errores = []
        if lon_r != lon_o: errores.append("longitud_fichero")
        if nom_r != nom_o: errores.append("nombre_fichero")
        if fec_r != fec_o: errores.append("fecha_hora")
        if cc_r[:256] != cc_o: errores.append("clave_sesion_cifrada")
        if iv_r != iv_o:   errores.append("iv")
        if lc_r != lc_o:   errores.append("len_clave_cifrada")
        if not errores:
            log_ok("serializacion/deserializacion de todos los campos: OK")
        else:
            log_fail("campos con error: " + ", ".join(errores))
    except Exception as e:
        log_fail("excepcion al serializar metadatos", str(e))

    try:
        u64max = 2**64 - 1
        raw    = empaquetar_meta(u64max, "t.bin", "2025-01-01 00:00:00",
                                 bytes(256), bytes(TAM_IV), 256)
        lon_r  = desempaquetar_meta(raw)[0]
        if lon_r == u64max:
            log_ok("longitud_fichero uint64 maximo: OK")
        else:
            log_fail("overflow en longitud_fichero uint64")
    except Exception as e:
        log_fail("excepcion con uint64 maximo", str(e))

# ─────────────────────────────────────────────
# bloque 6: conexion TCP basica
# ─────────────────────────────────────────────

def test_conexion_tcp():
    separador("BLOQUE 6 - CONEXION TCP")

    resultado = {}

    def srv_echo():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", PUERTO_TEST))
            s.listen(1)
            s.settimeout(TIMEOUT_SOCKET)
            conn, _ = s.accept()
            datos = conn.recv(1024)
            conn.send(datos)
            conn.close()
            s.close()
            resultado["datos"] = datos
        except Exception as e:
            resultado["error"] = str(e)

    hilo = threading.Thread(target=srv_echo, daemon=True)
    hilo.start()
    time.sleep(0.2)

    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.settimeout(TIMEOUT_SOCKET)
        cli.connect(("127.0.0.1", PUERTO_TEST))
        msg = b"test_tcp_apl02"
        cli.send(msg)
        resp = cli.recv(1024)
        cli.close()
        hilo.join(timeout=3)
        if resp == msg:
            log_ok("conexion TCP loopback echo: OK")
        else:
            log_fail("el echo no devolvio el mismo mensaje")
    except Exception as e:
        log_fail("error en conexion TCP basica", str(e))

    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.settimeout(2)
        try:
            cli.connect(("127.0.0.1", PUERTO_TEST + 1))
            log_fail("conexion a puerto cerrado no deberia funcionar")
        except (ConnectionRefusedError, socket.timeout, OSError):
            log_ok("conexion a puerto cerrado falla correctamente")
        finally:
            cli.close()
    except Exception as e:
        log_warn("prueba puerto cerrado: " + str(e))

# ─────────────────────────────────────────────
# bloque 7: flujo completo (simulacion python)
# ─────────────────────────────────────────────

def srv_transferencia(puerto, resultado):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", puerto))
        s.listen(1)
        s.settimeout(10)
        conn, _ = s.accept()
        conn.settimeout(10)

        raw = b""
        while len(raw) < TAM_META:
            c = conn.recv(TAM_META - len(raw))
            if not c:
                break
            raw += c

        longitud, nombre, fecha, cc, iv, lc = desempaquetar_meta(raw)
        priv      = cargar_clave_privada()
        clave_ses = descifrar_con_rsa(priv, cc[:lc])
        conn.send(struct.pack("i", 1))

        tam_c = struct.unpack("Q", conn.recv(8))[0]
        datos_c = b""
        while len(datos_c) < tam_c:
            c = conn.recv(min(4096, tam_c - len(datos_c)))
            if not c:
                break
            datos_c += c

        datos_d = descifrar_aes(clave_ses, iv, datos_c)
        conn.close()
        s.close()
        resultado.update({"ok": True, "datos": datos_d,
                          "longitud": longitud, "nombre": nombre})
    except Exception as e:
        resultado.update({"ok": False, "error": str(e)})

def cli_transferencia(puerto, fichero_bytes, nombre):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("127.0.0.1", puerto))

        clave_ses = os.urandom(TAM_CLAVE_AES)
        iv        = os.urandom(TAM_IV)
        pub       = cargar_clave_publica()
        cc        = cifrar_con_rsa(pub, clave_ses)
        lc        = len(cc)

        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        raw   = empaquetar_meta(len(fichero_bytes), nombre, fecha, cc, iv, lc)
        s.send(raw)

        resp = struct.unpack("i", s.recv(4))[0]
        if resp != 1:
            s.close()
            return False

        enc = cifrar_aes(clave_ses, iv, fichero_bytes)
        s.send(struct.pack("Q", len(enc)))
        s.sendall(enc)
        s.close()
        return True
    except Exception:
        return False

def flujo_completo(nombre_test, datos, puerto):
    res = {}
    hilo = threading.Thread(target=srv_transferencia,
                            args=(puerto, res), daemon=True)
    hilo.start()
    time.sleep(0.3)
    ok_cli = cli_transferencia(puerto, datos, "prueba.bin")
    hilo.join(timeout=15)

    if not ok_cli:
        log_fail(nombre_test + ": el cliente fallo")
        return
    if not res.get("ok"):
        log_fail(nombre_test + ": el servidor fallo", res.get("error", ""))
        return
    if res.get("datos") == datos:
        log_ok(nombre_test + " (" + str(round(len(datos)/1024, 1)) + " KB): OK")
    else:
        log_fail(nombre_test + ": datos no coinciden",
                 "env=" + str(len(datos)) + " B recv=" + str(len(res.get("datos", b""))) + " B")

def test_flujo_completo():
    separador("BLOQUE 7 - FLUJO COMPLETO DE TRANSFERENCIA CIFRADA (python)")

    casos = [
        ("texto 512 B",         b"Practica APL02 " * 34,       PUERTO_TEST + 10),
        ("binario 10 KB",       os.urandom(10 * 1024),          PUERTO_TEST + 11),
        ("binario 500 KB",      os.urandom(500 * 1024),         PUERTO_TEST + 12),
        ("binario 2 MB",        os.urandom(2 * 1024 * 1024),    PUERTO_TEST + 13),
        ("exactamente 16 B",    os.urandom(16),                 PUERTO_TEST + 14),
        ("1 byte",              os.urandom(1),                  PUERTO_TEST + 15),
        ("ceros 1 KB",          bytes(1024),                    PUERTO_TEST + 16),
    ]
    for nombre, datos, puerto in casos:
        flujo_completo(nombre, datos, puerto)
        time.sleep(0.4)

# ─────────────────────────────────────────────
# bloque 8: integridad SHA-256
# ─────────────────────────────────────────────

def test_integridad():
    separador("BLOQUE 8 - INTEGRIDAD END-TO-END (SHA-256)")

    for kb, puerto in [(4, PUERTO_TEST + 20), (128, PUERTO_TEST + 21)]:
        datos  = os.urandom(kb * 1024)
        h_orig = hashlib.sha256(datos).hexdigest()
        res    = {}
        hilo   = threading.Thread(target=srv_transferencia,
                                  args=(puerto, res), daemon=True)
        hilo.start()
        time.sleep(0.3)
        cli_transferencia(puerto, datos, "hash.bin")
        hilo.join(timeout=15)

        if res.get("ok"):
            h_recv = hashlib.sha256(res["datos"]).hexdigest()
            if h_orig == h_recv:
                log_ok("integridad SHA-256 " + str(kb) + " KB: hashes identicos")
            else:
                log_fail("integridad " + str(kb) + " KB: hashes distintos",
                         "orig=" + h_orig[:16] + "... recv=" + h_recv[:16] + "...")
        else:
            log_fail("integridad " + str(kb) + " KB: servidor fallo", res.get("error", ""))
        time.sleep(0.4)

# ─────────────────────────────────────────────
# bloque 9: servidor iterativo
# ─────────────────────────────────────────────

def srv_iterativo(puerto, n_clientes, resultados):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", puerto))
        s.listen(5)
        s.settimeout(15)
        priv = cargar_clave_privada()

        for _ in range(n_clientes):
            conn, _ = s.accept()
            conn.settimeout(10)
            raw = b""
            while len(raw) < TAM_META:
                c = conn.recv(TAM_META - len(raw))
                if not c:
                    break
                raw += c
            _, _, _, cc, iv, lc = desempaquetar_meta(raw)
            clave = descifrar_con_rsa(priv, cc[:lc])
            conn.send(struct.pack("i", 1))
            tam_c = struct.unpack("Q", conn.recv(8))[0]
            datos_c = b""
            while len(datos_c) < tam_c:
                c = conn.recv(min(4096, tam_c - len(datos_c)))
                if not c:
                    break
                datos_c += c
            resultados.append(descifrar_aes(clave, iv, datos_c))
            conn.close()
        s.close()
    except Exception:
        resultados.append(None)

def test_servidor_iterativo():
    separador("BLOQUE 9 - SERVIDOR ITERATIVO (multiples clientes)")

    n       = 3
    puerto  = PUERTO_TEST + 30
    envios  = [os.urandom(random.randint(512, 4096)) for _ in range(n)]
    recvs   = []

    hilo = threading.Thread(target=srv_iterativo,
                            args=(puerto, n, recvs), daemon=True)
    hilo.start()
    time.sleep(0.3)

    for i, datos in enumerate(envios):
        time.sleep(0.1)
        cli_transferencia(puerto, datos, "cli_" + str(i) + ".bin")

    hilo.join(timeout=20)

    if len(recvs) == n:
        ok_n = sum(1 for o, r in zip(envios, recvs) if r and o == r)
        if ok_n == n:
            log_ok("servidor iterativo: " + str(n) + " clientes atendidos correctamente")
        else:
            log_fail("servidor iterativo: " + str(ok_n) + "/" + str(n) + " transferencias correctas")
    else:
        log_fail("servidor iterativo: " + str(len(recvs)) + "/" + str(n) + " resultados recibidos")

# ─────────────────────────────────────────────
# bloque 10: prueba de los ejecutables reales
# ─────────────────────────────────────────────

def test_ejecutables_reales():
    separador("BLOQUE 10 - PRUEBA DE EJECUTABLES REALES (servidor.exe + cliente.exe)")

    if not os.path.isfile(RUTA_SERVIDOR_EXE):
        log_warn("servidor.exe no encontrado -> bloque de compilacion fallo, omitiendo")
        return
    if not os.path.isfile(RUTA_CLIENTE_EXE):
        log_warn("cliente.exe no encontrado -> bloque de compilacion fallo, omitiendo")
        return

    ruta_fichero_prueba = os.path.join(DIR_TEMP, "fichero_prueba_real.bin")
    contenido_original  = os.urandom(64 * 1024)
    with open(ruta_fichero_prueba, "wb") as f:
        f.write(contenido_original)
    log_info("fichero de prueba creado: 64 KB")

    log_info("arrancando servidor.exe...")
    proc_srv = None
    try:
        proc_srv = subprocess.Popen(
            [RUTA_SERVIDOR_EXE],
            cwd=DIR_TEMP,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
    except Exception as e:
        log_fail("no se pudo arrancar servidor.exe", str(e))
        return

    time.sleep(1.5)

    if proc_srv.poll() is not None:
        out, err = proc_srv.communicate()
        log_fail("servidor.exe termino prematuramente",
                 (out + err).decode(errors="replace")[:300])
        return
    log_ok("servidor.exe arrancado y en escucha")

    log_info("ejecutando cliente.exe...")
    try:
        r_cli = subprocess.run(
            [RUTA_CLIENTE_EXE, ruta_fichero_prueba],
            cwd=DIR_TEMP,
            capture_output=True,
            timeout=20
        )
        if r_cli.returncode == 0:
            log_ok("cliente.exe termino con exito (returncode=0)")
        else:
            salida = (r_cli.stdout + r_cli.stderr).decode(errors="replace")
            log_fail("cliente.exe termino con error", salida[:300])
    except subprocess.TimeoutExpired:
        log_fail("cliente.exe no termino en 20 segundos (timeout)")
    except Exception as e:
        log_fail("excepcion ejecutando cliente.exe", str(e))
    finally:
        try:
            proc_srv.terminate()
            proc_srv.wait(timeout=3)
        except Exception:
            proc_srv.kill()

    nombre_recibido = "recibido_fichero_prueba_real.bin"
    ruta_recibido   = os.path.join(DIR_TEMP, nombre_recibido)

    if os.path.isfile(ruta_recibido):
        with open(ruta_recibido, "rb") as f:
            contenido_recibido = f.read()

        h_orig = hashlib.sha256(contenido_original).hexdigest()
        h_recv = hashlib.sha256(contenido_recibido).hexdigest()

        if h_orig == h_recv:
            log_ok("fichero recibido y descifrado por servidor.exe: integridad SHA-256 OK")
            log_ok("hash: " + h_orig[:32] + "...")
        else:
            log_fail("el fichero descifrado por servidor.exe no coincide con el original",
                     "orig=" + h_orig[:16] + "... recv=" + h_recv[:16] + "...")
    else:
        log_warn("no se encontro '" + nombre_recibido + "' en " + DIR_TEMP)
        log_warn("puede que el servidor no guardo el fichero o uso otro nombre")

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
        print("  " + verde(negrita("todo correcto")))
    elif fail <= 3:
        print("  " + amarillo(negrita("hay fallos menores que revisar")))
    else:
        print("  " + rojo(negrita("hay fallos importantes")))
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
    print(borde_mid + "  TESTER APL02 - TRANSFERENCIA FICHEROS CIFRADA          " + borde_mid)
    print(borde_mid + "  Ingenieria de Protocolos de Comunicaciones             " + borde_mid)
    print(borde_bot)
    print()
    print("  inicio: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    try:
        test_entorno()
        claves_ok = test_generacion_claves()

        if not claves_ok or not CRYPTO_OK:
            log_fail("se omiten el resto de bloques por fallo en entorno o claves")
        else:
            compilacion_ok = test_compilacion()
            test_cifrado_rsa()
            test_cifrado_aes()
            test_estructura_metadatos()
            test_conexion_tcp()
            test_flujo_completo()
            test_integridad()
            test_servidor_iterativo()
            if compilacion_ok:
                test_ejecutables_reales()
            else:
                log_warn("bloque 10 omitido: la compilacion fallo")

    except KeyboardInterrupt:
        print("\n  " + amarillo("pruebas interrumpidas por el usuario"))
    finally:
        try:
            shutil.rmtree(DIR_TEMP)
        except Exception:
            pass
        resumen_final()