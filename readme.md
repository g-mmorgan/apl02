# APL02 - Transferencia de Ficheros con Cifrado Híbrido
## Ingeniería de Protocolos de Comunicaciones

## Guía compilación

## Paso 1 — Generar las claves RSA y el certificado

Ejecutar **una sola vez** antes de compilar. Genera la clave privada RSA-2048
del servidor y su certificado autofirmado X.509 (contiene la clave publica):


openssl genrsa -out server_key.pem 2048
openssl req -new -x509 -key server_key.pem -out server_cert.pem -days 365 -subj "/CN=Servidor/O=APL02/C=ES"


Ficheros generados:
- `server_key.pem` -> clave privada RSA del servidor (solo la usa el servidor)
- `server_cert.pem` -> certificado X.509 con la clave publica (lo usa el cliente)

> IMPORTANTE: estos ficheros deben estar en el mismo directorio que los ejecutables.

## Paso 2 — Compilar el servidor


gcc servidor.c crypto_utils.c -o servidor.exe -I"C:\OpenSSL-Win64\include" -L"C:\OpenSSL-Win64\lib" -lws2_32 -lssl -lcrypto


---

## Paso 3 — Compilar el cliente


gcc cliente.c crypto_utils.c -o cliente.exe -I"C:\OpenSSL-Win64\include" -L"C:\OpenSSL-Win64\lib" -lws2_32 -lssl -lcrypto


---

## Paso 4 — Ejecutar

Abrir **dos ventanas de CMD** en el directorio del proyecto.

**Ventana 1 — Servidor** (arrancar primero):

servidor.exe


**Ventana 2 — Cliente** (una vez el servidor esta escuchando):

cliente.exe ruta\al\fichero.txt


Ejemplo:

cliente.exe C:\Users\W11\Documents\prueba.pdf


El servidor guardara el fichero descifrado con el prefijo `recibido_` en el
directorio donde se ejecute. Por ejemplo: `recibido_prueba.pdf`

## Tester individual

Para ejecutar tester:

$pip install cryptography

$python tester_practica.py
