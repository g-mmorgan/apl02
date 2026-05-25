# tester exhaustivo para la practica APL02
# hace todo automaticamente:
#   - genera los .a de mingw desde las dlls si no estan en apl02/libs/
#   - instala dependencias python si faltan
#   - genera claves RSA con openssl
#   - compila servidor.exe y cliente.exe con gcc
#   - prueba cifrado RSA, AES, serializacion, TCP y flujo completo
#   - prueba los ejecutables reales con un fichero de verdad
#
# requisitos: python 3.x, openssl en PATH, gcc en PATH, dlltool en PATH
# ejecutar:   python tester.py   (desde la carpeta apl02/)

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

# rutas fijas de openssl en la VM de la asignatura
OPENSSL_DIR = r"C:\OpenSSL-Win64"
OPENSSL_INC = os.path.join(OPENSSL_DIR, "include")
OPENSSL_BIN = os.path.join(OPENSSL_DIR, "bin")

# carpeta libs/ dentro del propio proyecto: aqui guardamos los .a generados con dlltool
# esto permite que el proyecto sea autocontenido y no dependa del entorno del profesor
DIR_PROYECTO = os.path.dirname(os.path.abspath(__file__))
LIBS_LOCALES  = os.path.join(DIR_PROYECTO, "libs")

# rutas de las dlls de openssl que hay en la VM (instalacion MSVC, solo dlls disponibles)
DLL_SSL    = os.path.join(OPENSSL_BIN, "libssl-1_1-x64.dll")
DLL_CRYPTO = os.path.join(OPENSSL_BIN, "libcrypto-1_1-x64.dll")
DEF_SSL    = os.path.join(OPENSSL_DIR, "lib", "libssl.def")
DEF_CRYPTO = os.path.join(OPENSSL_DIR, "lib", "libcrypto.def")

# rutas de los .a que queremos generar (compatibles con mingw 32 bits)
LIB_SSL_A    = os.path.join(LIBS_LOCALES, "libssl.a")
LIB_CRYPTO_A = os.path.join(LIBS_LOCALES, "libcrypto.a")

# una vez tengamos los .a, el -L del compilador apunta a LIBS_LOCALES
# si no existen los .a, el tester intenta generarlos antes de compilar
OPENSSL_LIB = LIBS_LOCALES

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
        # mostramos el detalle linea a linea para que sea legible
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
# bloque -1: preparacion de libs mingw
# genera los .a desde las dlls de openssl si no existen ya
# esto resuelve el problema de que la instalacion de openssl en la VM
# solo tiene .lib de MSVC, no .a compatibles con mingw
# ─────────────────────────────────────────────

def preparar_libs_mingw():
    separador("BLOQUE PREVIO - PREPARACION DE LIBS MINGW")

    # comprobamos si dlltool esta disponible (viene con mingw)
    try:
        r = subprocess.run(["dlltool", "--version"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            log_fail("dlltool no responde correctamente",
                     "returncode=" + str(r.returncode) + " stderr=" + r.stderr.strip())
            return False
        log_ok("dlltool disponible: " + r.stdout.splitlines()[0].strip())
    except FileNotFoundError:
        log_fail("dlltool no encontrado en PATH",
                 "dlltool viene con MinGW, comprueba que MinGW/bin esta en el PATH")
        return False
    except Exception as e:
        log_fail("excepcion al comprobar dlltool", str(e))
        return False

    # creamos la carpeta libs/ si no existe
    if not os.path.isdir(LIBS_LOCALES):
        try:
            os.makedirs(LIBS_LOCALES)
            log_info("carpeta libs/ creada: " + LIBS_LOCALES)
        except Exception as e:
            log_fail("no se pudo crear la carpeta libs/", str(e))
            return False
    else:
        log_info("carpeta libs/ ya existe: " + LIBS_LOCALES)

    # funcion auxiliar para generar un .a desde una dll y su .def
    def generar_lib_a(nombre, dll, def_file, salida_a):
        if os.path.isfile(salida_a):
            tam = os.path.getsize(salida_a)
            log_ok(nombre + " ya existe en libs/ (" + str(tam // 1024) + " KB), no se regenera")
            return True

        # comprobamos que existen la dll y el .def antes de llamar a dlltool
        if not os.path.isfile(dll):
            log_fail("dll no encontrada: " + dll,
                     "la instalacion de openssl en C:\\OpenSSL-Win64\\bin parece incompleta")
            return False
        if not os.path.isfile(def_file):
            log_fail("fichero .def no encontrado: " + def_file,
                     "necesario para que dlltool sepa los simbolos exportados por la dll")
            return False

        log_info("generando " + nombre + " desde " + os.path.basename(dll) + "...")
        # dlltool -D <dll> -d <def> -l <salida.a>
        # -D: nombre de la dll en runtime
        # -d: fichero .def con los simbolos exportados
        # -l: fichero .a de salida (import library compatible con mingw)
        cmd = ["dlltool",
               "-D", dll,
               "-d", def_file,
               "-l", salida_a]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and os.path.isfile(salida_a):
                tam = os.path.getsize(salida_a)
                log_ok(nombre + " generado correctamente (" + str(tam // 1024) + " KB)")
                log_info("ruta: " + salida_a)
                return True
            else:
                log_fail("dlltool fallo al generar " + nombre,
                         "returncode=" + str(r.returncode))
                if r.stdout.strip():
                    log_fail("stdout dlltool:", r.stdout.strip()[:500])
                if r.stderr.strip():
                    log_fail("stderr dlltool:", r.stderr.strip()[:500])
                return False
        except Exception as e:
            log_fail("excepcion ejecutando dlltool para " + nombre, str(e))
            return False

    ok_ssl    = generar_lib_a("libssl.a",    DLL_SSL,    DEF_SSL,    LIB_SSL_A)
    ok_crypto = generar_lib_a("libcrypto.a", DLL_CRYPTO, DEF_CRYPTO, LIB_CRYPTO_A)

    if not ok_ssl or not ok_crypto:
        log_fail("no se pudieron preparar las libs mingw",
                 "sin libssl.a y libcrypto.a la compilacion fallara")
        log_info("causa probable: la VM no tiene las dlls o .def de openssl en las rutas esperadas")
        log_info("rutas buscadas:")
        log_info("  dll ssl:    " + DLL_SSL)
        log_info("  dll crypto: " + DLL_CRYPTO)
        log_info("  def ssl:    " + DEF_SSL)
        log_info("  def crypto: " + DEF_CRYPTO)
        return False

    # copiamos las dlls de openssl y la dll del runtime de gcc a libs/
    # libgcc_s_dw2-1.dll es el runtime de excepciones de mingw 4.8.1 (dw2 = dwarf2)
    # sin ella los .exe compilados con este gcc fallan con 0xc000007b al arrancar
    mingw_bin = os.path.dirname(
        subprocess.run(["where", "gcc"], capture_output=True, text=True).stdout.strip()
    )
    dlls_necesarias = [
        (DLL_SSL,    "libssl-1_1-x64.dll"),
        (DLL_CRYPTO, "libcrypto-1_1-x64.dll"),
        (os.path.join(mingw_bin, "libgcc_s_dw2-1.dll"), "libgcc_s_dw2-1.dll"),
    ]
    for dll_src, dll_nombre in dlls_necesarias:
        dst = os.path.join(LIBS_LOCALES, dll_nombre)
        if not os.path.isfile(dst):
            if os.path.isfile(dll_src):
                try:
                    shutil.copy2(dll_src, dst)
                    log_ok("dll copiada a libs/: " + dll_nombre)
                except Exception as e:
                    log_warn("no se pudo copiar " + dll_nombre + " a libs/", str(e))
            else:
                log_warn("dll no encontrada, no se puede copiar: " + dll_src)
        else:
            log_ok("dll ya en libs/: " + dll_nombre)

    log_ok("libs mingw listas en: " + LIBS_LOCALES)
    return True

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
        r = subprocess.run(["openssl", "version"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log_ok("openssl: " + r.stdout.strip())
        else:
            log_fail("openssl no responde",
                     "returncode=" + str(r.returncode) + " stderr=" + r.stderr.strip())
    except FileNotFoundError:
        log_fail("openssl no encontrado en PATH",
                 "ruta esperada: " + os.path.join(OPENSSL_BIN, "openssl.exe"))

    try:
        r = subprocess.run(["gcc", "--version"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log_ok("gcc: " + r.stdout.splitlines()[0].strip())
            # comprobamos la arquitectura de gcc (debe ser mingw32 en esta VM)
            r2 = subprocess.run(["gcc", "-dumpmachine"],
                                 capture_output=True, text=True, timeout=5)
            if r2.returncode == 0:
                log_info("arquitectura gcc: " + r2.stdout.strip())
        else:
            log_fail("gcc no responde",
                     "returncode=" + str(r.returncode) + " stderr=" + r.stderr.strip())
    except FileNotFoundError:
        log_fail("gcc no encontrado en PATH",
                 "instala MinGW y anyadelo al PATH del sistema")

    try:
        r = subprocess.run(["dlltool", "--version"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log_ok("dlltool disponible (necesario para generar .a desde dlls)")
        else:
            log_warn("dlltool no responde correctamente",
                     "puede que la generacion de libs falle")
    except FileNotFoundError:
        log_warn("dlltool no encontrado en PATH",
                 "dlltool viene incluido con MinGW en la misma carpeta que gcc")

    if os.path.isdir(OPENSSL_INC):
        log_ok("directorio include de OpenSSL encontrado: " + OPENSSL_INC)
        # comprobamos que los headers clave existen
        for h in ["openssl/ssl.h", "openssl/evp.h", "openssl/aes.h", "openssl/rsa.h"]:
            rh = os.path.join(OPENSSL_INC, h)
            if os.path.isfile(rh):
                log_info("  header OK: " + h)
            else:
                log_warn("  header NO encontrado: " + h,
                         "la compilacion puede fallar si se incluye este header")
    else:
        log_warn("directorio include no encontrado: " + OPENSSL_INC,
                 "la compilacion fallara sin los headers de openssl")

    if os.path.isdir(LIBS_LOCALES):
        log_ok("carpeta libs/ encontrada: " + LIBS_LOCALES)
        for lib in ["libssl.a", "libcrypto.a"]:
            rlib = os.path.join(LIBS_LOCALES, lib)
            if os.path.isfile(rlib):
                log_ok("  " + lib + " presente (" + str(os.path.getsize(rlib) // 1024) + " KB)")
            else:
                log_warn("  " + lib + " NO encontrado en libs/",
                         "se intentara generar en el bloque previo")
    else:
        log_warn("carpeta libs/ no existe todavia",
                 "se creara automaticamente en el bloque previo")

    global CRYPTO_OK
    if CRYPTO_OK:
        log_ok("libreria python 'cryptography' disponible")
    else:
        log_info("instalando libreria 'cryptography'...")
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "cryptography"],
                capture_output=True, text=True, check=True
            )
            log_ok("libreria 'cryptography' instalada")
            log_info("reinicia el tester para que surta efecto")
            sys.exit(0)
        except subprocess.CalledProcessError as e:
            log_fail("no se pudo instalar 'cryptography'",
                     (e.stdout or "") + (e.stderr or ""))
            sys.exit(1)
        except Exception as e:
            log_fail("excepcion al instalar 'cryptography'", str(e))
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
            log_warn("openssl verify no paso",
                     "stdout: " + r.stdout.strip() + "\nstderr: " + r.stderr.strip())
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
            log_fail("no se pudo extraer la clave publica",
                     "returncode=" + str(r.returncode) + "\n" + r.stderr.strip())
    except Exception as e:
        log_fail("excepcion al extraer clave publica", str(e))

    return True

# ─────────────────────────────────────────────
# bloque 2: compilacion con gcc
# ─────────────────────────────────────────────

RUTA_SERVIDOR_EXE = os.path.join(DIR_TEMP, "servidor.exe")
RUTA_CLIENTE_EXE  = os.path.join(DIR_TEMP, "cliente.exe")

def test_compilacion():
    separador("BLOQUE 2 - COMPILACION CON GCC")

    # verificamos que todos los ficheros fuente necesarios existen
    fuentes_necesarias = ["common.h", "crypto_utils.h",
                          "crypto_utils.c", "servidor.c", "cliente.c"]
    todos_presentes = True
    for f in fuentes_necesarias:
        ruta = os.path.join(DIR_PROYECTO, f)
        if os.path.isfile(ruta):
            log_ok("fuente encontrado: " + f
                   + " (" + str(os.path.getsize(ruta)) + " bytes)")
        else:
            log_fail("fuente NO encontrado: " + f,
                     "debe estar en: " + DIR_PROYECTO)
            todos_presentes = False

    if not todos_presentes:
        log_fail("compilacion abortada: faltan ficheros fuente")
        return False

    # verificamos que los .a existen en libs/ antes de compilar
    if not os.path.isfile(LIB_SSL_A) or not os.path.isfile(LIB_CRYPTO_A):
        log_fail("libs mingw no disponibles en libs/",
                 "libssl.a o libcrypto.a no encontrados en " + LIBS_LOCALES
                 + "\nel bloque previo de preparacion de libs debio haber fallado")
        return False

    log_info("usando libs en: " + LIBS_LOCALES)
    log_info("usando headers en: " + OPENSSL_INC)

    # flags de compilacion para mingw + openssl 1.1.1 en windows
    # -lws2_32: winsock2 (sockets windows)
    # -lgdi32 y -lcrypt32: dependencias de openssl en windows
    # el orden de las -l importa en gcc: las libs van despues de los fuentes
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
        log_info("comando: " + " ".join(cmd))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=60, cwd=DIR_PROYECTO)
            exe_ok = r.returncode == 0 and os.path.isfile(ruta_salida)
            if exe_ok:
                tam = os.path.getsize(ruta_salida)
                log_ok(nombre_exe + " compilado (" + str(tam // 1024) + " KB)")
                # mostramos todos los warnings para que el alumno pueda corregirlos
                if r.stderr and "warning" in r.stderr.lower():
                    for linea in r.stderr.splitlines():
                        if "warning" in linea.lower():
                            log_warn("gcc warning: " + linea.strip()[:150])
                # copiamos las dlls al directorio temporal donde correran los .exe
                # incluimos libgcc_s_dw2-1.dll (runtime de mingw 4.8.1)
                # sin alguna de estas dlls los .exe fallan con error 0xc000007b
                for dll in ["libssl-1_1-x64.dll", "libcrypto-1_1-x64.dll",
                            "libgcc_s_dw2-1.dll"]:
                    src_dll = os.path.join(LIBS_LOCALES, dll)
                    dst_dll = os.path.join(DIR_TEMP, dll)
                    if os.path.isfile(src_dll) and not os.path.isfile(dst_dll):
                        try:
                            shutil.copy2(src_dll, dst_dll)
                            log_info("dll copiada al dir temporal: " + dll)
                        except Exception as ec:
                            log_warn("no se pudo copiar dll " + dll, str(ec))
                return True
            else:
                # mostramos TODA la salida del compilador para diagnosticar el error
                salida_completa = ""
                if r.stdout.strip():
                    salida_completa += "--- stdout ---\n" + r.stdout.strip()
                if r.stderr.strip():
                    salida_completa += "\n--- stderr ---\n" + r.stderr.strip()
                log_fail("error al compilar " + nombre_exe,
                         "returncode=" + str(r.returncode)
                         + "\n" + salida_completa[:3000])
                return False
        except subprocess.TimeoutExpired:
            log_fail("timeout al compilar " + nombre_exe,
                     "gcc no termino en 60 segundos, puede ser un cuelgue")
            return False
        except Exception as e:
            log_fail("excepcion al compilar " + nombre_exe, str(e))
            return False

    fuente_srv = os.path.join(DIR_PROYECTO, "servidor.c")
    ok_srv = compilar("servidor.exe", fuente_srv, RUTA_SERVIDOR_EXE)

    fuente_cli = os.path.join(DIR_PROYECTO, "cliente.c")
    ok_cli = compilar("cliente.exe", fuente_cli, RUTA_CLIENTE_EXE)

    if not ok_srv or not ok_cli:
        log_fail("compilacion fallida",
                 "revisa los errores arriba, especialmente los 'cannot find -lssl' o 'cannot find -lcrypto'"
                 + "\nsi aparecen, el bloque previo de libs fallo o los .a no se generaron correctamente")
        return False

    log_ok("compilacion completada: servidor.exe y cliente.exe listos")
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
        log_fail("no se pudieron cargar las claves RSA",
                 str(e) + "\ncomprueba que los ficheros .pem existen en: " + DIR_TEMP)
        return

    # prueba basica: cifrar con publica, descifrar con privada
    clave = os.urandom(TAM_CLAVE_AES)
    log_info("clave AES de prueba (hex): " + clave.hex()[:16] + "...")

    try:
        cifrado    = cifrar_con_rsa(pub, clave)
        descifrado = descifrar_con_rsa(priv, cifrado)
        if descifrado == clave:
            log_ok("cifrado/descifrado RSA-OAEP de clave AES-256 ("
                   + str(TAM_CLAVE_AES) + " B): OK")
        else:
            log_fail("la clave descifrada NO coincide con la original",
                     "original: " + clave.hex()
                     + "\ndescifrado: " + descifrado.hex())
    except Exception as e:
        log_fail("excepcion en cifrado/descifrado RSA", str(e))

    # verificamos que el bloque cifrado tiene el tamano correcto para RSA-2048
    try:
        cifrado = cifrar_con_rsa(pub, clave)
        esperado = TAM_CLAVE_RSA // 8  # 2048 bits / 8 = 256 bytes
        if len(cifrado) == esperado:
            log_ok("tamano bloque RSA cifrado: " + str(len(cifrado))
                   + " bytes (correcto RSA-" + str(TAM_CLAVE_RSA) + ")")
        else:
            log_warn("tamano inesperado del bloque cifrado",
                     "obtenido: " + str(len(cifrado)) + " bytes"
                     + "\nesperado: " + str(esperado) + " bytes")
    except Exception as e:
        log_fail("error al verificar tamano del bloque RSA", str(e))

    # descifrar con clave incorrecta debe fallar (seguridad)
    try:
        priv_falsa = rsa.generate_private_key(65537, TAM_CLAVE_RSA, default_backend())
        cifrado    = cifrar_con_rsa(pub, clave)
        try:
            resultado = descifrar_con_rsa(priv_falsa, cifrado)
            log_fail("descifrado con clave incorrecta NO fallo (problema de seguridad)",
                     "resultado obtenido: " + resultado.hex()[:32])
        except Exception:
            log_ok("descifrado con clave RSA incorrecta falla correctamente")
    except Exception as e:
        log_warn("no se pudo probar la clave incorrecta", str(e))

    # oaep es probabilistico: dos cifrados del mismo dato deben ser distintos
    try:
        c1 = cifrar_con_rsa(pub, clave)
        c2 = cifrar_con_rsa(pub, clave)
        if c1 != c2:
            log_ok("RSA-OAEP es probabilistico: dos cifrados del mismo dato son distintos")
        else:
            log_warn("los dos cifrados son identicos",
                     "el padding aleatorio no esta funcionando correctamente")
    except Exception as e:
        log_warn("no se pudo probar el caracter probabilistico de OAEP", str(e))

# ─────────────────────────────────────────────
# bloque 4: cifrado AES-256-CBC
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
    dec     = Cipher(algorithms.AES(clave), modes.CBC(iv),
                     backend=default_backend()).decryptor()
    datos_p = dec.update(cifrado) + dec.finalize()
    unpad   = sp.PKCS7(128).unpadder()
    return unpad.update(datos_p) + unpad.finalize()

def test_cifrado_aes():
    separador("BLOQUE 4 - CIFRADO / DESCIFRADO AES-256-CBC")

    clave = os.urandom(TAM_CLAVE_AES)
    iv    = os.urandom(TAM_IV)

    log_info("clave AES (hex): " + clave.hex())
    log_info("IV (hex):        " + iv.hex())

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
                log_ok("AES " + nombre + ": OK (" + str(round(ms, 1)) + " ms)"
                       + " | orig=" + str(len(datos)) + "B cifrado=" + str(len(enc)) + "B")
            else:
                log_fail("AES " + nombre + ": datos NO coinciden tras descifrar",
                         "bytes enviados: " + str(len(datos))
                         + "\nbytes recibidos: " + str(len(dec))
                         + "\nprimeros bytes orig (hex): " + datos[:16].hex()
                         + "\nprimeros bytes desc (hex): " + dec[:16].hex())
        except Exception as e:
            log_fail("AES " + nombre + ": excepcion", str(e))

    # prueba de integridad SHA-256 para detectar corrupcion silenciosa
    try:
        datos  = os.urandom(4096)
        h_orig = hashlib.sha256(datos).hexdigest()
        enc    = cifrar_aes(clave, iv, datos)
        dec    = descifrar_aes(clave, iv, enc)
        h_desc = hashlib.sha256(dec).hexdigest()
        if h_orig == h_desc:
            log_ok("integridad SHA-256 tras cifrado/descifrado AES: OK")
            log_info("hash: " + h_orig[:32] + "...")
        else:
            log_fail("hash SHA-256 NO coincide: datos corrompidos en AES",
                     "hash original:   " + h_orig
                     + "\nhash descifrado: " + h_desc)
    except Exception as e:
        log_fail("excepcion en prueba SHA-256 de AES", str(e))

    # prueba con IV distinto debe producir datos distintos (modo CBC correcto)
    try:
        datos  = os.urandom(64)
        iv2    = os.urandom(TAM_IV)
        enc1   = cifrar_aes(clave, iv,  datos)
        enc2   = cifrar_aes(clave, iv2, datos)
        if enc1 != enc2:
            log_ok("AES con IV distinto produce cifrado distinto (CBC correcto)")
        else:
            log_warn("AES con IV distinto produce el mismo cifrado",
                     "el modo CBC no esta usando el IV correctamente")
    except Exception as e:
        log_warn("no se pudo probar el efecto del IV en CBC", str(e))

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
    separador("BLOQUE 5 - ESTRUCTURA DE METADATOS")

    log_info("tamano esperado del struct MetadatosFichero: 560 bytes")
    log_info("formato struct: " + FORMATO_META)

    if TAM_META == 560:
        log_ok("tamano struct MetadatosFichero: " + str(TAM_META) + " bytes (correcto)")
    else:
        log_fail("tamano struct incorrecto",
                 "obtenido: " + str(TAM_META) + " bytes"
                 + "\nesperado: 560 bytes"
                 + "\nrevisa los campos de MetadatosFichero en common.h")

    # prueba de serializacion/deserializacion con valores reales
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
        if lon_r != lon_o:
            errores.append("longitud_fichero: enviado=" + str(lon_o)
                           + " recibido=" + str(lon_r))
        if nom_r != nom_o:
            errores.append("nombre_fichero: enviado='" + nom_o
                           + "' recibido='" + nom_r + "'")
        if fec_r != fec_o:
            errores.append("fecha_hora: enviado='" + fec_o
                           + "' recibido='" + fec_r + "'")
        if cc_r[:256] != cc_o:
            errores.append("clave_sesion_cifrada: los 256 bytes no coinciden")
        if iv_r != iv_o:
            errores.append("iv: enviado=" + iv_o.hex()
                           + " recibido=" + iv_r.hex())
        if lc_r != lc_o:
            errores.append("len_clave_cifrada: enviado=" + str(lc_o)
                           + " recibido=" + str(lc_r))

        if not errores:
            log_ok("serializacion/deserializacion de todos los campos: OK")
        else:
            for e in errores:
                log_fail("campo con error: " + e)
    except Exception as e:
        log_fail("excepcion al serializar/deserializar metadatos", str(e))

    # prueba con el valor maximo de uint64 para verificar que no hay overflow
    try:
        u64max = 2**64 - 1
        raw    = empaquetar_meta(u64max, "t.bin", "2025-01-01 00:00:00",
                                 bytes(256), bytes(TAM_IV), 256)
        lon_r  = desempaquetar_meta(raw)[0]
        if lon_r == u64max:
            log_ok("longitud_fichero uint64 maximo (2^64-1): OK")
        else:
            log_fail("overflow en longitud_fichero uint64",
                     "enviado: " + str(u64max) + "\nrecibido: " + str(lon_r))
    except Exception as e:
        log_fail("excepcion con uint64 maximo", str(e))

    # prueba de alineacion: el struct debe ser compacto sin padding del compilador C
    log_info("desglose de campos del struct (560 bytes total):")
    log_info("  longitud_fichero [8B] + nombre_fichero [256B] + fecha_hora [20B]")
    log_info("  + clave_sesion_cifrada [256B] + iv [16B] + len_clave_cifrada [4B]")
    log_info("  = 8 + 256 + 20 + 256 + 16 + 4 = 560 bytes")

# ─────────────────────────────────────────────
# bloque 6: conexion TCP basica
# ─────────────────────────────────────────────

def test_conexion_tcp():
    separador("BLOQUE 6 - CONEXION TCP")

    puerto = PUERTO_TEST + 1
    log_info("probando conexion TCP loopback en puerto " + str(puerto))

    # servidor echo minimo: recibe datos y los devuelve tal cual
    def servidor_echo(p, listo):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
            s.listen(1)
            s.settimeout(5)
            listo.set()  # avisamos al cliente que ya estamos escuchando
            conn, addr = s.accept()
            log_info("servidor echo: cliente conectado desde " + str(addr))
            conn.settimeout(5)
            datos = conn.recv(1024)
            log_info("servidor echo: recibidos " + str(len(datos)) + " bytes, devolviendo")
            conn.sendall(datos)
            conn.close()
            s.close()
        except Exception as e:
            log_warn("excepcion en servidor echo", str(e))

    listo = threading.Event()
    hilo = threading.Thread(target=servidor_echo, args=(puerto, listo), daemon=True)
    hilo.start()

    # esperamos a que el servidor este listo antes de conectar
    if not listo.wait(timeout=3):
        log_fail("el servidor echo no arranco en 3 segundos")
        return

    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(TIMEOUT_SOCKET)
        c.connect(("127.0.0.1", puerto))
        mensaje = b"prueba TCP APL02 - loopback OK"
        c.sendall(mensaje)
        respuesta = c.recv(1024)
        c.close()
        hilo.join(timeout=3)

        if respuesta == mensaje:
            log_ok("conexion TCP loopback echo: OK"
                   + " (" + str(len(mensaje)) + " bytes enviados y recibidos)")
        else:
            log_fail("los datos recibidos no coinciden con los enviados",
                     "enviado: " + mensaje.hex()
                     + "\nrecibido: " + respuesta.hex())
    except socket.timeout:
        log_fail("timeout en la conexion TCP loopback",
                 "el servidor echo no respondio en " + str(TIMEOUT_SOCKET) + " segundos")
    except ConnectionRefusedError:
        log_fail("conexion TCP rechazada",
                 "el servidor echo no esta escuchando en el puerto " + str(puerto))
    except Exception as e:
        log_fail("excepcion en la prueba TCP", str(e))

    # verificamos que conectar a un puerto cerrado falla correctamente
    puerto_cerrado = PUERTO_TEST + 2
    log_info("probando que la conexion a puerto cerrado ("
             + str(puerto_cerrado) + ") falla correctamente")
    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(2)
        c.connect(("127.0.0.1", puerto_cerrado))
        c.close()
        log_fail("conexion a puerto cerrado no fallo (anomalia)",
                 "el sistema operativo deberia rechazar la conexion")
    except (ConnectionRefusedError, socket.timeout, OSError):
        log_ok("conexion a puerto cerrado falla correctamente")
    except Exception as e:
        log_warn("excepcion inesperada al probar puerto cerrado", str(e))

# ─────────────────────────────────────────────
# bloque 7: flujo completo de transferencia cifrada (python)
# ─────────────────────────────────────────────

def srv_transferencia(puerto, resultado):
    # simula el comportamiento del servidor.c en python puro
    # recibe metadatos, descifra la clave RSA, acepta, recibe datos cifrados, descifra
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", puerto))
        s.listen(1)
        s.settimeout(10)
        conn, addr = s.accept()
        conn.settimeout(10)

        # recibimos la estructura de metadatos completa (560 bytes)
        raw = b""
        while len(raw) < TAM_META:
            c = conn.recv(TAM_META - len(raw))
            if not c:
                raise Exception("conexion cerrada antes de recibir metadatos completos"
                                + " (recibidos " + str(len(raw)) + "/" + str(TAM_META) + " bytes)")
            raw += c

        longitud, nombre, fecha, cc, iv, lc = desempaquetar_meta(raw)

        # descifrar la clave de sesion AES con la clave privada RSA
        priv      = cargar_clave_privada()
        clave_ses = descifrar_con_rsa(priv, cc[:lc])

        # enviamos aceptacion al cliente (RespuestaServidor.aceptado = 1)
        conn.send(struct.pack("i", 1))

        # recibimos el tamano del bloque cifrado (uint64, 8 bytes)
        raw_tam = conn.recv(8)
        if len(raw_tam) < 8:
            raise Exception("no se recibieron los 8 bytes del tamano del bloque cifrado")
        tam_c = struct.unpack("Q", raw_tam)[0]

        # recibimos el contenido cifrado completo
        datos_c = b""
        while len(datos_c) < tam_c:
            chunk = conn.recv(min(4096, tam_c - len(datos_c)))
            if not chunk:
                raise Exception("conexion cerrada durante recepcion de datos cifrados"
                                + " (recibidos " + str(len(datos_c)) + "/" + str(tam_c) + " bytes)")
            datos_c += chunk

        # desciframos con AES-256-CBC usando la clave y el IV de los metadatos
        datos_d = descifrar_aes(clave_ses, iv, datos_c)
        conn.close()
        s.close()
        resultado.update({
            "ok":       True,
            "datos":    datos_d,
            "longitud": longitud,
            "nombre":   nombre,
            "fecha":    fecha
        })
    except Exception as e:
        resultado.update({"ok": False, "error": str(e)})

def cli_transferencia(puerto, fichero_bytes, nombre):
    # simula el comportamiento del cliente.c en python puro
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("127.0.0.1", puerto))

        # generamos clave de sesion AES-256 e IV aleatorios
        clave_ses = os.urandom(TAM_CLAVE_AES)
        iv        = os.urandom(TAM_IV)

        # ciframos la clave de sesion con la clave publica RSA del servidor
        pub = cargar_clave_publica()
        cc  = cifrar_con_rsa(pub, clave_ses)
        lc  = len(cc)

        # rellenamos y enviamos la estructura de metadatos
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        raw   = empaquetar_meta(len(fichero_bytes), nombre, fecha, cc, iv, lc)
        s.send(raw)

        # esperamos la aceptacion del servidor
        raw_resp = s.recv(4)
        if len(raw_resp) < 4:
            s.close()
            return False, "respuesta del servidor incompleta (" + str(len(raw_resp)) + " bytes)"
        resp = struct.unpack("i", raw_resp)[0]
        if resp != 1:
            s.close()
            return False, "servidor rechazo la transferencia (aceptado=" + str(resp) + ")"

        # ciframos el fichero con AES-256-CBC
        enc = cifrar_aes(clave_ses, iv, fichero_bytes)

        # enviamos primero el tamano del bloque cifrado (uint64) y luego los datos
        s.send(struct.pack("Q", len(enc)))
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
        return
    if not res.get("ok"):
        log_fail(nombre_test + " (" + kb_str + "): servidor fallo",
                 res.get("error", "sin detalle"))
        return
    if res.get("datos") == datos:
        log_ok(nombre_test + " (" + kb_str + "): OK")
    else:
        recv_datos = res.get("datos", b"")
        log_fail(nombre_test + " (" + kb_str + "): datos NO coinciden",
                 "bytes enviados: " + str(len(datos))
                 + "\nbytes recibidos: " + str(len(recv_datos))
                 + "\nhash orig: " + hashlib.sha256(datos).hexdigest()[:16] + "..."
                 + "\nhash recv: " + hashlib.sha256(recv_datos).hexdigest()[:16] + "...")

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
# bloque 8: integridad SHA-256 end-to-end
# ─────────────────────────────────────────────

def test_integridad():
    separador("BLOQUE 8 - INTEGRIDAD END-TO-END (SHA-256)")

    casos = [(4, PUERTO_TEST + 20), (128, PUERTO_TEST + 21)]

    for kb, puerto in casos:
        datos  = os.urandom(kb * 1024)
        h_orig = hashlib.sha256(datos).hexdigest()
        log_info("SHA-256 " + str(kb) + " KB original: " + h_orig[:32] + "...")

        res  = {}
        hilo = threading.Thread(target=srv_transferencia,
                                args=(puerto, res), daemon=True)
        hilo.start()
        time.sleep(0.3)

        ok_cli, err_cli = cli_transferencia(puerto, datos, "hash.bin")
        hilo.join(timeout=15)

        if not ok_cli:
            log_fail("integridad " + str(kb) + " KB: cliente fallo", err_cli)
        elif not res.get("ok"):
            log_fail("integridad " + str(kb) + " KB: servidor fallo",
                     res.get("error", "sin detalle"))
        else:
            h_recv = hashlib.sha256(res["datos"]).hexdigest()
            log_info("SHA-256 " + str(kb) + " KB recibido: " + h_recv[:32] + "...")
            if h_orig == h_recv:
                log_ok("integridad SHA-256 " + str(kb) + " KB: hashes identicos")
            else:
                log_fail("integridad " + str(kb) + " KB: hashes DISTINTOS (corrupcion de datos)",
                         "hash orig: " + h_orig
                         + "\nhash recv: " + h_recv)
        time.sleep(0.4)

# ─────────────────────────────────────────────
# bloque 9: servidor iterativo (multiples clientes)
# ─────────────────────────────────────────────

def srv_iterativo(puerto, n_clientes, resultados):
    # el servidor iterativo atiende a los clientes de uno en uno en bucle
    # corresponde al patron del temario: accept -> atender -> close -> accept
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

            # recibimos metadatos del cliente i
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

            raw_tam = conn.recv(8)
            tam_c   = struct.unpack("Q", raw_tam)[0]

            datos_c = b""
            while len(datos_c) < tam_c:
                chunk = conn.recv(min(4096, tam_c - len(datos_c)))
                if not chunk:
                    break
                datos_c += chunk

            try:
                datos_d = descifrar_aes(clave, iv, datos_c)
                resultados.append(datos_d)
            except Exception as e:
                resultados.append(None)

            conn.close()

        s.close()
    except Exception as e:
        # apendamos None para los clientes que no se pudieron atender
        while len(resultados) < n_clientes:
            resultados.append(None)

def test_servidor_iterativo():
    separador("BLOQUE 9 - SERVIDOR ITERATIVO (multiples clientes)")

    n      = 3
    puerto = PUERTO_TEST + 30
    envios = [os.urandom(random.randint(512, 4096)) for _ in range(n)]
    recvs  = []

    log_info("probando servidor iterativo con " + str(n) + " clientes secuenciales")
    for i, d in enumerate(envios):
        log_info("cliente " + str(i + 1) + ": " + str(len(d)) + " bytes a enviar")

    hilo = threading.Thread(target=srv_iterativo,
                            args=(puerto, n, recvs), daemon=True)
    hilo.start()
    time.sleep(0.3)

    for i, datos in enumerate(envios):
        time.sleep(0.2)
        ok_cli, err_cli = cli_transferencia(puerto, datos,
                                            "cli_" + str(i) + ".bin")
        if not ok_cli:
            log_warn("cliente " + str(i + 1) + " fallo al enviar", err_cli)

    hilo.join(timeout=20)

    if len(recvs) == n:
        fallos = []
        for i, (o, r) in enumerate(zip(envios, recvs)):
            if r is None:
                fallos.append("cliente " + str(i + 1) + ": servidor devolvio None")
            elif o != r:
                fallos.append("cliente " + str(i + 1) + ": datos no coinciden"
                              + " (env=" + str(len(o)) + "B recv=" + str(len(r)) + "B)")
        if not fallos:
            log_ok("servidor iterativo: " + str(n) + " clientes atendidos correctamente")
        else:
            for f in fallos:
                log_fail(f)
    else:
        log_fail("servidor iterativo: resultados incompletos",
                 "esperados: " + str(n) + " resultados"
                 + "\nrecibidos: " + str(len(recvs))
                 + "\npuede que el servidor petara antes de atender a todos los clientes")

# ─────────────────────────────────────────────
# bloque 10: prueba de los ejecutables reales
# ─────────────────────────────────────────────

def test_ejecutables_reales():
    separador("BLOQUE 10 - PRUEBA DE EJECUTABLES REALES (servidor.exe + cliente.exe)")

    if not os.path.isfile(RUTA_SERVIDOR_EXE):
        log_warn("servidor.exe no encontrado en " + RUTA_SERVIDOR_EXE)
        return
    if not os.path.isfile(RUTA_CLIENTE_EXE):
        log_warn("cliente.exe no encontrado en " + RUTA_CLIENTE_EXE)
        return

    log_info("servidor.exe: " + RUTA_SERVIDOR_EXE
             + " (" + str(os.path.getsize(RUTA_SERVIDOR_EXE) // 1024) + " KB)")
    log_info("cliente.exe:  " + RUTA_CLIENTE_EXE
             + " (" + str(os.path.getsize(RUTA_CLIENTE_EXE) // 1024) + " KB)")

    # comprobamos que las tres dlls necesarias estan en el dir temporal
    # libgcc_s_dw2-1.dll es el runtime de mingw, sin ella 0xc000007b al arrancar
    for dll in ["libssl-1_1-x64.dll", "libcrypto-1_1-x64.dll", "libgcc_s_dw2-1.dll"]:
        ruta_dll = os.path.join(DIR_TEMP, dll)
        if os.path.isfile(ruta_dll):
            log_ok("dll en dir temporal: " + dll)
        else:
            log_warn("dll NO encontrada en dir temporal: " + dll,
                     "el ejecutable puede fallar al arrancar si no encuentra las dlls"
                     + "\nruta buscada: " + ruta_dll)
            # intentamos copiarla desde libs/ como ultimo recurso
            src = os.path.join(LIBS_LOCALES, dll)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, ruta_dll)
                    log_info("dll copiada desde libs/ como fallback: " + dll)
                except Exception as ec:
                    log_warn("no se pudo copiar dll", str(ec))

    # copiamos los .pem al dir temporal para que los .exe los encuentren
    # servidor.exe busca server_key.pem y cliente.exe busca server_cert.pem
    for pem_src, pem_nom in [(RUTA_CLAVE_PRIVADA, "server_key.pem"),
                              (RUTA_CERTIFICADO,   "server_cert.pem")]:
        dst = os.path.join(DIR_TEMP, pem_nom)
        if not os.path.isfile(dst):
            try:
                shutil.copy2(pem_src, dst)
                log_info("PEM copiado al dir temporal: " + pem_nom)
            except Exception as e:
                log_fail("no se pudo copiar " + pem_nom + " al dir temporal", str(e))
                return

    # creamos el fichero de prueba (64 KB de datos aleatorios)
    ruta_fichero_prueba = os.path.join(DIR_TEMP, "fichero_prueba_real.bin")
    contenido_original  = os.urandom(64 * 1024)
    with open(ruta_fichero_prueba, "wb") as f:
        f.write(contenido_original)
    log_ok("fichero de prueba creado: 64 KB ("
           + hashlib.sha256(contenido_original).hexdigest()[:16] + "...)")

    # arrancamos el servidor.exe en background
    log_info("arrancando servidor.exe en background...")
    proc_srv = None
    try:
        proc_srv = subprocess.Popen(
            [RUTA_SERVIDOR_EXE],
            cwd=DIR_TEMP,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
        log_info("PID del servidor.exe: " + str(proc_srv.pid))
    except Exception as e:
        log_fail("no se pudo arrancar servidor.exe", str(e))
        return

    # esperamos a que el servidor este escuchando
    time.sleep(1.5)

    if proc_srv.poll() is not None:
        # el proceso ya termino, algo fallo al arrancar
        out, err = proc_srv.communicate()
        salida = (out + err).decode(errors="replace")
        log_fail("servidor.exe termino prematuramente (no llego a escuchar)",
                 "returncode: " + str(proc_srv.returncode)
                 + "\nsalida del proceso:\n" + salida[:1000])
        log_info("causas habituales:")
        log_info("  - las dlls libssl/libcrypto no estan en el dir temporal")
        log_info("  - server_key.pem no encontrado en el dir de trabajo")
        log_info("  - puerto 8080 ya en uso por otro proceso")
        return
    log_ok("servidor.exe arrancado y en escucha (PID " + str(proc_srv.pid) + ")")

    # ejecutamos el cliente.exe con el fichero de prueba
    log_info("ejecutando cliente.exe con fichero de 64 KB...")
    try:
        r_cli = subprocess.run(
            [RUTA_CLIENTE_EXE, ruta_fichero_prueba],
            cwd=DIR_TEMP,
            capture_output=True,
            timeout=20
        )
        salida_cli = (r_cli.stdout + r_cli.stderr).decode(errors="replace")
        if r_cli.returncode == 0:
            log_ok("cliente.exe termino con exito (returncode=0)")
        else:
            log_fail("cliente.exe termino con error",
                     "returncode: " + str(r_cli.returncode)
                     + "\nsalida del cliente:\n" + salida_cli[:1000])
        # mostramos la salida del cliente para depurar
        if salida_cli.strip():
            log_info("--- salida cliente.exe ---")
            for linea in salida_cli.strip().splitlines()[:20]:
                log_info("  " + linea)
    except subprocess.TimeoutExpired:
        log_fail("cliente.exe no termino en 20 segundos (timeout)",
                 "puede que el servidor no este respondiendo o hay un deadlock")
    except Exception as e:
        log_fail("excepcion ejecutando cliente.exe", str(e))
    finally:
        # paramos el servidor.exe y mostramos su salida para depurar
        try:
            proc_srv.terminate()
            out_srv, err_srv = proc_srv.communicate(timeout=3)
            salida_srv = (out_srv + err_srv).decode(errors="replace")
            if salida_srv.strip():
                log_info("--- salida servidor.exe ---")
                for linea in salida_srv.strip().splitlines()[:20]:
                    log_info("  " + linea)
        except Exception:
            try:
                proc_srv.kill()
            except Exception:
                pass

    # verificamos que el servidor guardo el fichero descifrado correctamente
    nombre_recibido = "recibido_fichero_prueba_real.bin"
    ruta_recibido   = os.path.join(DIR_TEMP, nombre_recibido)

    if os.path.isfile(ruta_recibido):
        with open(ruta_recibido, "rb") as f:
            contenido_recibido = f.read()

        h_orig = hashlib.sha256(contenido_original).hexdigest()
        h_recv = hashlib.sha256(contenido_recibido).hexdigest()

        log_info("hash original:  " + h_orig)
        log_info("hash recibido:  " + h_recv)

        if h_orig == h_recv:
            log_ok("fichero descifrado por servidor.exe: integridad SHA-256 OK")
        else:
            log_fail("el fichero descifrado NO coincide con el original",
                     "tamanyo orig: " + str(len(contenido_original)) + " bytes"
                     + "\ntamanyo recv: " + str(len(contenido_recibido)) + " bytes"
                     + "\nhash orig: " + h_orig
                     + "\nhash recv: " + h_recv)
    else:
        log_warn("fichero recibido no encontrado: " + nombre_recibido,
                 "ruta buscada: " + ruta_recibido
                 + "\nel servidor puede haber usado otro nombre o no guardo el fichero"
                 + "\ncontenido del dir temporal:")
        try:
            for f in os.listdir(DIR_TEMP):
                log_info("  " + f + " ("
                         + str(os.path.getsize(os.path.join(DIR_TEMP, f))) + " bytes)")
        except Exception:
            pass

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
        # el bloque previo genera los .a de mingw automaticamente si no existen
        # esto hace que el proyecto sea autocontenido y no dependa del entorno
        libs_ok = preparar_libs_mingw()

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
                log_warn("bloque 10 omitido: la compilacion fallo"
                         + "\nrevisa los errores del bloque 2 y el bloque previo de libs")

    except KeyboardInterrupt:
        print("\n  " + amarillo("pruebas interrumpidas por el usuario"))
    finally:
        try:
            shutil.rmtree(DIR_TEMP)
        except Exception:
            pass
        resumen_final()