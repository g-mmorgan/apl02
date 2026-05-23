#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common.h"
#include "crypto_utils.h"

// enlazar la libreria Winsock automaticamente (equivale a -lws2_32)
#pragma comment(lib, "ws2_32.lib")

// ruta al fichero PEM con la clave privada RSA del servidor
// el cliente usa el certificado (server_cert.pem) y el servidor la clave privada
#define RUTA_CLAVE_PRIVADA "server_key.pem"

// tamanyo del buffer de recepcion en bytes (4 KB)
#define TAM_BUFFER_RECV 4096

// recibe exactamente 'len' bytes del socket
// recv() puede devolver menos bytes de los pedidos (comportamiento normal en TCP)

static int recibir_todo(SOCKET sock, unsigned char *buf, int len)
{
    int total    = 0;
    int restante = len;

    while (restante > 0) {
        // recv es la llamada Winsock equivalente a read() en Berkeley sockets
        // (temario: RECV System Call - pag INTERFACE SOCKETS)
        int recibido = recv(sock, (char *)(buf + total), restante, 0);
        if (recibido <= 0) {
            // recibido == 0 -> el cliente cerro la conexion
            // recibido < 0  -> error de red
            return -1;
        }
        total    += recibido;
        restante -= recibido;
    }
    return total;
}
 
// logica completa de atencion a un cliente

static void atender_cliente(SOCKET sock_cliente)
{
    MetadatosFichero meta;
    RespuestaServidor resp;

    // paso 1: recibir la estructura de metadatos del cliente
    // usamos recibir_todo porque el struct puede llegar fragmentado en TCP
    printf("[servidor] esperando metadatos del fichero...\n");
    if (recibir_todo(sock_cliente, (unsigned char *)&meta, sizeof(meta)) < 0) {
        printf("[servidor] error al recibir metadatos\n");
        return;
    }

    // mostramos la informacion del fichero que nos manda el cliente
    printf("[servidor] fichero    : %s\n",  meta.nombre_fichero);
    printf("[servidor] tamano     : %llu bytes\n", (unsigned long long)meta.longitud_fichero);
    printf("[servidor] fecha/hora : %s\n",  meta.fecha_hora);
    printf("[servidor] len clave cifrada: %d bytes\n", meta.len_clave_cifrada);

    // paso 2: descifrar la clave de sesion AES con nuestra clave privada RSA
    // el cliente cifro la clave AES con nuestra clave publica (del certificado)
    // nosotros la desciframos con nuestra clave privada (distribucion de clave)
    unsigned char clave_sesion[TAM_CLAVE_SESION];
    int len_desc = descifrar_clave_rsa(RUTA_CLAVE_PRIVADA,
                                       meta.clave_sesion_cifrada,
                                       meta.len_clave_cifrada,
                                       clave_sesion);
    if (len_desc < 0) {
        printf("[servidor] error al descifrar la clave de sesion RSA\n");
        resp.aceptado = 0;
        // enviamos rechazo al cliente y salimos
        send(sock_cliente, (char *)&resp, sizeof(resp), 0);
        return;
    }
    printf("[servidor] clave de sesion AES descifrada OK (%d bytes)\n", len_desc);

    // paso 3: enviar aceptacion al cliente
    // el enunciado dice: "el servidor respondera al cliente aceptando la transferencia"
    resp.aceptado = 1;
    // send es la llamada Winsock para enviar datos (temario: SEND System Call)
    if (send(sock_cliente, (char *)&resp, sizeof(resp), 0) == SOCKET_ERROR) {
        printf("[servidor] error al enviar aceptacion\n");
        return;
    }
    printf("[servidor] aceptacion enviada al cliente\n");

    // paso 4: recibir el tamano del bloque cifrado (8 bytes, uint64)
    // el cliente nos manda primero el tamano para que sepamos cuanto leer
    uint64_t tam_cifrado = 0;
    if (recibir_todo(sock_cliente, (unsigned char *)&tam_cifrado,
                     sizeof(tam_cifrado)) < 0) {
        printf("[servidor] error al recibir tamano del fichero cifrado\n");
        return;
    }
    printf("[servidor] tamano del bloque cifrado a recibir: %llu bytes\n",
           (unsigned long long)tam_cifrado);

    // paso 5: recibir el fichero cifrado completo en bloques
    // usamos malloc dinamico porque el fichero puede ser grande
    unsigned char *buf_cifrado = (unsigned char *)malloc((size_t)tam_cifrado);
    if (!buf_cifrado) {
        printf("[servidor] error de memoria al reservar buffer de recepcion\n");
        return;
    }

    // recibimos el contenido cifrado completo (puede llegar en varios recv)
    if (recibir_todo(sock_cliente, buf_cifrado, (int)tam_cifrado) < 0) {
        printf("[servidor] error al recibir el contenido del fichero cifrado\n");
        free(buf_cifrado);
        return;
    }
    printf("[servidor] fichero cifrado recibido (%llu bytes)\n",
           (unsigned long long)tam_cifrado);

    // paso 6: descifrar el fichero con AES-256-CBC
    // usamos la clave de sesion que descifro RSA y el IV que mando el cliente
    // el buf descifrado puede ser hasta un bloque AES menor que el cifrado
    unsigned char *buf_descifrado = (unsigned char *)malloc((size_t)tam_cifrado);
    if (!buf_descifrado) {
        printf("[servidor] error de memoria al reservar buffer de descifrado\n");
        free(buf_cifrado);
        return;
    }

    int len_descifrado = descifrar_aes(clave_sesion, meta.iv,
                                       buf_cifrado, (int)tam_cifrado,
                                       buf_descifrado);
    free(buf_cifrado); // ya no necesitamos el buffer cifrado

    if (len_descifrado < 0) {
        printf("[servidor] error al descifrar el fichero con AES\n");
        free(buf_descifrado);
        return;
    }
    printf("[servidor] fichero descifrado OK (%d bytes)\n", len_descifrado);

    // paso 7: guardar el fichero descifrado en disco
    // guardamos con el nombre original que nos mando el cliente en los metadatos
    // anyadimos prefijo "recibido_" para distinguirlo del original
    char nombre_salida[MAX_NOMBRE + 16];
    snprintf(nombre_salida, sizeof(nombre_salida), "recibido_%s", meta.nombre_fichero);

    FILE *f_salida = fopen(nombre_salida, "wb");
    if (!f_salida) {
        printf("[servidor] error al crear el fichero de salida: %s\n", nombre_salida);
        free(buf_descifrado);
        return;
    }

    size_t escritos = fwrite(buf_descifrado, 1, (size_t)len_descifrado, f_salida);
    fclose(f_salida);
    free(buf_descifrado);

    if ((int)escritos != len_descifrado) {
        printf("[servidor] error al escribir el fichero: escribio %zu de %d bytes\n",
               escritos, len_descifrado);
        return;
    }

    printf("[servidor] fichero guardado como: %s\n", nombre_salida);
    printf("[servidor] transferencia completada con exito\n");
}

// implementa el algoritmo del temario:
//   socket() -> bind() -> listen() -> while(1): accept() -> atender -> close(ssock)
int main(void)
{
    WSADATA wsa_data;
    SOCKET  sock_escucha;   // socket pasivo de escucha (master socket del temario)
    SOCKET  sock_cliente;   // socket activo para cada cliente (slave socket)
    struct sockaddr_in dir_servidor; // direccion local del servidor
    struct sockaddr_in dir_cliente;  // direccion del cliente que se conecta
    int tam_dir;

    //inicializacion de Winsock
    // en Windows hay que inicializar la libreria antes de usar cualquier socket
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("[servidor] error al inicializar Winsock: %d\n", WSAGetLastError());
        return 1;
    }
    printf("[servidor] Winsock inicializado (v%d.%d)\n",
           LOBYTE(wsa_data.wVersion), HIBYTE(wsa_data.wVersion));

    //creacion del socket TCP
    // AF_INET -> familia IPv4 (temario: struct sockaddr_in, sin_family = AF_INET)
    // SOCK_STREAM -> orientado a conexion, protocolo TCP
    sock_escucha = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_escucha == INVALID_SOCKET) {
        printf("[servidor] error al crear socket: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[servidor] socket TCP creado\n");

    // opcion SO_REUSEADDR: permite reusar el puerto si el servidor se reinicia rapido
    // evita el error "bind failed: address already in use"
    int opcion = 1;
    setsockopt(sock_escucha, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&opcion, sizeof(opcion));

    // rellenar la estructura de direccion del servidor
    // el temario muestra: sin_family = AF_INET, sin_addr = INADDR_ANY, sin_port = htons()
    // INADDR_ANY -> acepta conexiones en cualquier interfaz de red local
    memset(&dir_servidor, 0, sizeof(dir_servidor));
    dir_servidor.sin_family      = AF_INET;
    dir_servidor.sin_addr.s_addr = INADDR_ANY;
    dir_servidor.sin_port        = htons(PUERTO);

    // bind: asociar el socket al puerto
    if (bind(sock_escucha, (struct sockaddr *)&dir_servidor,
             sizeof(dir_servidor)) == SOCKET_ERROR) {
        printf("[servidor] error en bind: %d\n", WSAGetLastError());
        closesocket(sock_escucha);
        WSACleanup();
        return 1;
    }

    // listen: poner el socket en modo pasivo de escucha
    // backlog = 5 -> cola de hasta 5 conexiones pendientes
    if (listen(sock_escucha, 5) == SOCKET_ERROR) {
        printf("[servidor] error en listen: %d\n", WSAGetLastError());
        closesocket(sock_escucha);
        WSACleanup();
        return 1;
    }
    printf("[servidor] escuchando en puerto %d...\n", PUERTO);

    // bucle principal del servidor iterativo
    // el temario define el servidor iterativo como:
    // "acepta una conexion y obtiene un nuevo socket para atender esa peticion,
    //  cuando finaliza con un cliente cierra la conexion y vuelve a acceptar"
    while (1) {
        tam_dir = sizeof(dir_cliente);

        // accept: bloquea hasta que llega una conexion de un cliente
        // devuelve un nuevo socket dedicado a este cliente (slave socket)
        sock_cliente = accept(sock_escucha,
                              (struct sockaddr *)&dir_cliente,
                              &tam_dir);
        if (sock_cliente == INVALID_SOCKET) {
            printf("[servidor] error en accept: %d\n", WSAGetLastError());
            continue; // seguimos esperando mas conexiones
        }

        printf("[servidor] cliente conectado desde %s:%d\n",
               inet_ntoa(dir_cliente.sin_addr),
               ntohs(dir_cliente.sin_port));

        // atender al cliente (servidor iterativo: un cliente a la vez)
        atender_cliente(sock_cliente);

        // cerramos el socket del cliente cuando terminamos con el
        closesocket(sock_cliente);
        printf("[servidor] conexion con cliente cerrada\n\n");

        // al ser servidor iterativo, volvemos al accept() a esperar el siguiente
    }

    // este codigo no se alcanza normalmente, pero limpiamos por completitud
    closesocket(sock_escucha);
    WSACleanup();
    return 0;
}