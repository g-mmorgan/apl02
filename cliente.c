#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// RAND_bytes: generacion de bytes aleatorios criptograficamente seguros
#include <openssl/rand.h>
// ERR para imprimir errores de OpenSSL
#include <openssl/err.h>

#include "common.h"
#include "crypto_utils.h"

// enlazar la libreria Winsock automaticamente
#pragma comment(lib, "ws2_32.lib")

// ip del servidor (loopback para pruebas en la misma maquina)
#define IP_SERVIDOR "127.0.0.1"

// ruta al certificado PEM del servidor (contiene su clave publica RSA)
// el cliente solo necesita el certificado, NO la clave privada del servidor
#define RUTA_CERT_SERVIDOR "server_cert.pem"

// enviar_todo: envia exactamente 'len' bytes por el socket
// send() puede enviar menos bytes de los pedidos si el buffer del kernel esta lleno

static int enviar_todo(SOCKET sock, const unsigned char *buf, int len)
{
    int total    = 0;
    int restante = len;

    while (restante > 0) {
        // send es la llamada Winsock para enviar datos por un socket TCP
        int enviados = send(sock, (const char *)(buf + total), restante, 0);
        if (enviados == SOCKET_ERROR || enviados <= 0) {
            return -1;
        }
        total    += enviados;
        restante -= enviados;
    }
    return total;
}


// leer_fichero: lee un fichero completo en un buffer dinamico
// devuelve el buffer (hay que hacer free) y el tamano por parametro
// devuelve NULL si hay error

static unsigned char *leer_fichero(const char *ruta, long *tamano)
{
    FILE *f = fopen(ruta, "rb");
    if (!f) {
        printf("[cliente] no se puede abrir el fichero: %s\n", ruta);
        return NULL;
    }

    // obtenemos el tamano del fichero buscando el final
    fseek(f, 0, SEEK_END);
    *tamano = ftell(f);
    fseek(f, 0, SEEK_SET); // volvemos al inicio

    if (*tamano <= 0) {
        printf("[cliente] fichero vacio o error al obtener tamano\n");
        fclose(f);
        return NULL;
    }

    // reservamos memoria para todo el contenido del fichero
    unsigned char *buf = (unsigned char *)malloc((size_t)*tamano);
    if (!buf) {
        printf("[cliente] error de memoria al leer el fichero\n");
        fclose(f);
        return NULL;
    }

    size_t leidos = fread(buf, 1, (size_t)*tamano, f);
    fclose(f);

    if ((long)leidos != *tamano) {
        printf("[cliente] error de lectura: leidos %zu de %ld bytes\n",
               leidos, *tamano);
        free(buf);
        return NULL;
    }

    return buf;
}

// obtener_nombre_fichero: extrae solo el nombre de fichero de una ruta
// por ejemplo "C:\Users\alumno\prueba.txt" -> "prueba.txt"
static const char *obtener_nombre_fichero(const char *ruta)
{
    // buscamos la ultima barra diagonal (Windows usa \ como separador)
    const char *p = strrchr(ruta, '\\');
    if (!p) p = strrchr(ruta, '/'); // por si acaso usan barra de Unix
    return p ? (p + 1) : ruta;     // si no hay barra, la ruta es el nombre
}


// main: punto de entrada del cliente TCP
// socket() -> connect() -> send()/recv() -> close()
// (SOFTWARE CLIENTE - algoritmo cliente orientado a conexion)

int main(int argc, char *argv[])
{
    // el fichero a transferir se pasa como primer argumento
    if (argc < 2) {
        printf("uso: cliente.exe <ruta_del_fichero>\n");
        printf("ejemplo: cliente.exe C:\\Users\\alumno\\documento.pdf\n");
        return 1;
    }
    const char *ruta_fichero = argv[1];

    //inicializacion de Winsock
    // obligatorio en Windows antes de cualquier operacion con sockets
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("[cliente] error al inicializar Winsock: %d\n", WSAGetLastError());
        return 1;
    }
    printf("[cliente] Winsock inicializado\n");

    //leer el fichero a transferir
    long tam_fichero = 0;
    unsigned char *buf_fichero = leer_fichero(ruta_fichero, &tam_fichero);
    if (!buf_fichero) {
        WSACleanup();
        return 1;
    }
    printf("[cliente] fichero leido: %s (%ld bytes)\n",
           ruta_fichero, tam_fichero);

    //generar clave de sesion AES-256 aleatoria
    // RAND_bytes de OpenSSL genera bytes criptograficamente seguros
    // esta es la clave simetrica que usaremos para cifrar el fichero
    unsigned char clave_sesion[TAM_CLAVE_SESION];
    unsigned char iv[TAM_IV];

    if (RAND_bytes(clave_sesion, TAM_CLAVE_SESION) != 1) {
        printf("[cliente] error al generar la clave de sesion AES\n");
        free(buf_fichero);
        WSACleanup();
        return 1;
    }
    // generamos tambien el IV aleatorio para AES-CBC
    if (RAND_bytes(iv, TAM_IV) != 1) {
        printf("[cliente] error al generar el IV para AES\n");
        free(buf_fichero);
        WSACleanup();
        return 1;
    }
    printf("[cliente] clave de sesion AES-256 e IV generados\n");

    //cifrar la clave de sesion con la clave publica RSA del servidor
    // usamos cifrar_clave_rsa de crypto_utils.c
    unsigned char clave_cifrada[TAM_CLAVE_CIFRADA];
    int len_clave_cifrada = cifrar_clave_rsa(RUTA_CERT_SERVIDOR,
                                              clave_sesion, TAM_CLAVE_SESION,
                                              clave_cifrada);
    if (len_clave_cifrada < 0) {
        printf("[cliente] error al cifrar la clave de sesion con RSA\n");
        free(buf_fichero);
        WSACleanup();
        return 1;
    }
    printf("[cliente] clave de sesion cifrada con RSA (%d bytes)\n",
           len_clave_cifrada);

    //rellenar la estructura de metadatos
    MetadatosFichero meta;
    memset(&meta, 0, sizeof(meta));

    // longitud del fichero original (antes de cifrar)
    meta.longitud_fichero = (uint64_t)tam_fichero;

    // nombre del fichero (solo el nombre, sin la ruta completa)
    const char *nombre = obtener_nombre_fichero(ruta_fichero);
    strncpy(meta.nombre_fichero, nombre, MAX_NOMBRE - 1);

    // fecha y hora actual de la transferencia en formato legible
    time_t t_actual = time(NULL);
    struct tm *tm_info = localtime(&t_actual);
    strftime(meta.fecha_hora, sizeof(meta.fecha_hora),
             "%Y-%m-%d %H:%M:%S", tm_info);

    // copiamos la clave cifrada y el IV a la estructura
    memcpy(meta.clave_sesion_cifrada, clave_cifrada, (size_t)len_clave_cifrada);
    memcpy(meta.iv, iv, TAM_IV);
    meta.len_clave_cifrada = len_clave_cifrada;

    printf("[cliente] metadatos preparados: '%s', %llu bytes, %s\n",
           meta.nombre_fichero,
           (unsigned long long)meta.longitud_fichero,
           meta.fecha_hora);

    //creacion del socket TCP
    // AF_INET = IPv4, SOCK_STREAM = TCP orientado a conexion
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("[cliente] error al crear socket: %d\n", WSAGetLastError());
        free(buf_fichero);
        WSACleanup();
        return 1;
    }

    // rellenar la direccion del servidor
    // usamos la estructura sockaddr_in del temario (WINSOCK2.H - struct sockaddr_in)
    struct sockaddr_in dir_servidor;
    memset(&dir_servidor, 0, sizeof(dir_servidor));
    dir_servidor.sin_family      = AF_INET;
    dir_servidor.sin_addr.s_addr = inet_addr(IP_SERVIDOR); // IPv4 del servidor
    dir_servidor.sin_port        = htons(PUERTO);          // puerto en orden de red

    //connect: establecer la conexion con el servidor
    printf("[cliente] conectando con %s:%d...\n", IP_SERVIDOR, PUERTO);
    if (connect(sock, (struct sockaddr *)&dir_servidor,
                sizeof(dir_servidor)) == SOCKET_ERROR) {
        printf("[cliente] error al conectar con el servidor: %d\n",
               WSAGetLastError());
        free(buf_fichero);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[cliente] conexion establecida con el servidor\n");

    //paso 1: enviar la estructura de metadatos al servidor
    // usamos enviar_todo para garantizar que se envia el struct completo
    if (enviar_todo(sock, (const unsigned char *)&meta, sizeof(meta)) < 0) {
        printf("[cliente] error al enviar metadatos\n");
        free(buf_fichero);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[cliente] metadatos enviados al servidor\n");

    //paso 2: esperar la aceptacion del servidor
    RespuestaServidor resp;
    int recibido = recv(sock, (char *)&resp, sizeof(resp), 0);
    if (recibido <= 0 || !resp.aceptado) {
        printf("[cliente] el servidor rechazo la transferencia o hubo error\n");
        free(buf_fichero);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[cliente] servidor acepto la transferencia\n");

    //paso 3: cifrar el fichero con AES-256-CBC
    // el bloque cifrado es siempre mayor que el original por el padding PKCS7
    // reservamos tam_fichero + 16 (un bloque AES de margen para el padding)
    size_t tam_buf_cifrado = (size_t)tam_fichero + AES_BLOCK_SIZE;
    unsigned char *buf_cifrado = (unsigned char *)malloc(tam_buf_cifrado);
    if (!buf_cifrado) {
        printf("[cliente] error de memoria para el buffer de cifrado\n");
        free(buf_fichero);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    int len_cifrado = cifrar_aes(clave_sesion, iv,
                                 buf_fichero, (int)tam_fichero,
                                 buf_cifrado);
    free(buf_fichero); // ya no necesitamos el buffer original

    if (len_cifrado < 0) {
        printf("[cliente] error al cifrar el fichero con AES\n");
        free(buf_cifrado);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[cliente] fichero cifrado con AES-256-CBC (%d bytes)\n", len_cifrado);

    //paso 4: enviar el tamano del bloque cifrado (8 bytes)
    // el servidor necesita saber cuantos bytes va a recibir antes de leerlos
    uint64_t tam_cifrado_u64 = (uint64_t)len_cifrado;
    if (enviar_todo(sock, (const unsigned char *)&tam_cifrado_u64,
                    sizeof(tam_cifrado_u64)) < 0) {
        printf("[cliente] error al enviar el tamano del bloque cifrado\n");
        free(buf_cifrado);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    //paso 5: enviar el fichero cifrado completo
    // usamos enviar_todo para garantizar que se envian todos los bytes
    printf("[cliente] enviando fichero cifrado...\n");
    if (enviar_todo(sock, buf_cifrado, len_cifrado) < 0) {
        printf("[cliente] error al enviar el fichero cifrado\n");
        free(buf_cifrado);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    free(buf_cifrado);
    printf("[cliente] fichero cifrado enviado correctamente\n");

    //cerrar la conexion
    closesocket(sock);
    WSACleanup();

    printf("[cliente] transferencia completada con exito\n");
    printf("[cliente] fichero: %s (%ld bytes originales)\n",
           obtener_nombre_fichero(ruta_fichero), tam_fichero);

    return 0;
}