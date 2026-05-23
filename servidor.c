// servidor iterativo TCP con Winsock
// recibe metadatos + fichero cifrado, lo descifra y lo guarda

#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "crypto_utils.h"

#pragma comment(lib, "ws2_32.lib")

// ruta a la clave privada RSA del servidor (para descifrar la clave de sesion)
#define RUTA_CLAVE_PRIVADA "server_key.pem"

// atiende a un cliente: recibe metadatos, acepta, recibe fichero cifrado y lo descifra
void atender_cliente(SOCKET cliente_sock) {

    MetadatosFichero meta;
    RespuestaServidor resp;

    // recibir la estructura de metadatos del cliente
    int recibido = recv(cliente_sock, (char *)&meta, sizeof(meta), 0);
    if (recibido <= 0) {
        printf("[servidor] error al recibir metadatos\n");
        return;
    }

    printf("[servidor] fichero: %s | tamano: %llu bytes | fecha: %s\n",
           meta.nombre_fichero, meta.longitud_fichero, meta.fecha_hora);

    // descifrar la clave de sesion con la clave privada RSA
    uint8_t clave_sesion[TAM_CLAVE_SESION];
    int len = descifrar_clave_rsa(RUTA_CLAVE_PRIVADA,
                                  meta.clave_sesion_cifrada,
                                  meta.len_clave_cifrada,
                                  clave_sesion);
    if (len < 0) {
        printf("[servidor] error al descifrar la clave de sesion\n");
        resp.aceptado = 0;
        send(cliente_sock, (char *)&resp, sizeof(resp), 0);
        return;
    }

    // enviar respuesta de aceptacion al cliente
    resp.aceptado = 1;
    send(cliente_sock, (char *)&resp, sizeof(resp), 0);

    // TODO persona A: recibir el fichero cifrado en bloques y descifrarlo con AES
    // usar meta.longitud_fichero para saber cuanto leer
    // usar meta.iv y clave_sesion para descifrar_aes()
    // guardar el resultado en un fichero con meta.nombre_fichero
}

int main(void) {

    WSADATA wsa;
    SOCKET sock_escucha, sock_cliente;
    struct sockaddr_in dir_servidor, dir_cliente;
    int tam_dir;

    // inicializar winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[servidor] error al iniciar winsock\n");
        return 1;
    }

    // crear socket TCP
    sock_escucha = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_escucha == INVALID_SOCKET) {
        printf("[servidor] error al crear socket\n");
        WSACleanup();
        return 1;
    }

    // configurar direccion y puerto
    memset(&dir_servidor, 0, sizeof(dir_servidor));
    dir_servidor.sin_family      = AF_INET;
    dir_servidor.sin_addr.s_addr = INADDR_ANY;
    dir_servidor.sin_port        = htons(PUERTO);

    // asociar socket al puerto
    if (bind(sock_escucha, (struct sockaddr *)&dir_servidor, sizeof(dir_servidor)) == SOCKET_ERROR) {
        printf("[servidor] error en bind\n");
        closesocket(sock_escucha);
        WSACleanup();
        return 1;
    }

    // poner en escucha (servidor iterativo, cola de 1)
    listen(sock_escucha, 1);
    printf("[servidor] esperando conexiones en puerto %d...\n", PUERTO);

    // bucle principal del servidor iterativo: atiende un cliente cada vez
    while (1) {
        tam_dir = sizeof(dir_cliente);
        sock_cliente = accept(sock_escucha, (struct sockaddr *)&dir_cliente, &tam_dir);
        if (sock_cliente == INVALID_SOCKET) {
            printf("[servidor] error en accept\n");
            continue;
        }
        printf("[servidor] cliente conectado\n");
        atender_cliente(sock_cliente);
        closesocket(sock_cliente);
        printf("[servidor] cliente desconectado\n");
    }

    closesocket(sock_escucha);
    WSACleanup();
    return 0;
}