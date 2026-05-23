// cliente TCP con Winsock
// envia metadatos + clave de sesion cifrada, luego envia el fichero cifrado

#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include "common.h"
#include "crypto_utils.h"

#pragma comment(lib, "ws2_32.lib")

// ip del servidor (loopback para pruebas)
#define IP_SERVIDOR "127.0.0.1"

// ruta al certificado publico del servidor para cifrar la clave de sesion
#define RUTA_CERT_SERVIDOR "server_cert.pem"

int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("uso: cliente.exe <ruta_fichero>\n");
        return 1;
    }

    const char *ruta_fichero = argv[1];

    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in dir_servidor;

    // inicializar winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[cliente] error al iniciar winsock\n");
        return 1;
    }

    // crear socket TCP
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("[cliente] error al crear socket\n");
        WSACleanup();
        return 1;
    }

    // configurar la direccion del servidor
    memset(&dir_servidor, 0, sizeof(dir_servidor));
    dir_servidor.sin_family      = AF_INET;
    dir_servidor.sin_addr.s_addr = inet_addr(IP_SERVIDOR);
    dir_servidor.sin_port        = htons(PUERTO);

    // conectar al servidor
    if (connect(sock, (struct sockaddr *)&dir_servidor, sizeof(dir_servidor)) == SOCKET_ERROR) {
        printf("[cliente] error al conectar con el servidor\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[cliente] conectado al servidor\n");

    // generar clave de sesion AES aleatoria con OpenSSL
    uint8_t clave_sesion[TAM_CLAVE_SESION];
    uint8_t iv[TAM_IV];
    RAND_bytes(clave_sesion, TAM_CLAVE_SESION); // clave aleatoria
    RAND_bytes(iv, TAM_IV);                     // iv aleatorio

    // rellenar la estructura de metadatos
    MetadatosFichero meta;
    memset(&meta, 0, sizeof(meta));

    // obtener tamano del fichero
    FILE *f = fopen(ruta_fichero, "rb");
    if (!f) {
        printf("[cliente] no se puede abrir el fichero\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    fseek(f, 0, SEEK_END);
    meta.longitud_fichero = (uint64_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    // nombre del fichero (solo el nombre, sin ruta)
    const char *nombre = strrchr(ruta_fichero, '\\');
    nombre = nombre ? nombre + 1 : ruta_fichero;
    strncpy(meta.nombre_fichero, nombre, MAX_NOMBRE - 1);

    // fecha y hora actual
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(meta.fecha_hora, sizeof(meta.fecha_hora), "%Y-%m-%d %H:%M:%S", tm_info);

    // copiar iv a la estructura
    memcpy(meta.iv, iv, TAM_IV);

    // cifrar la clave de sesion con la clave publica RSA del servidor
    meta.len_clave_cifrada = cifrar_clave_rsa(RUTA_CERT_SERVIDOR,
                                               clave_sesion, TAM_CLAVE_SESION,
                                               meta.clave_sesion_cifrada);
    if (meta.len_clave_cifrada < 0) {
        printf("[cliente] error al cifrar la clave de sesion\n");
        fclose(f);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // enviar metadatos al servidor
    send(sock, (char *)&meta, sizeof(meta), 0);

    // esperar respuesta del servidor
    RespuestaServidor resp;
    recv(sock, (char *)&resp, sizeof(resp), 0);
    if (!resp.aceptado) {
        printf("[cliente] servidor rechazo la transferencia\n");
        fclose(f);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[cliente] servidor acepto la transferencia, enviando fichero...\n");

    // TODO persona B: leer el fichero, cifrarlo con AES usando cifrar_aes() y enviarlo
    // se puede hacer en bloques o de golpe si el fichero no es muy grande

    fclose(f);
    closesocket(sock);
    WSACleanup();
    printf("[cliente] transferencia completada\n");
    return 0;
}