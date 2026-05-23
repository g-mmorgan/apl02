#ifndef COMMON_H
#define COMMON_H

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

// puerto de escucha del servidor
#define PUERTO 8080

// tamano maximo del nombre de fichero
#define MAX_NOMBRE 256

// tamano de la clave de sesion AES-256 en bytes
#define TAM_CLAVE_SESION 32

// tamano del IV para AES-CBC
#define TAM_IV 16

// tamano maximo de la clave de sesion cifrada con RSA (depende del tamano de la clave RSA)
// con RSA-2048 el output del cifrado es 256 bytes
#define TAM_CLAVE_CIFRADA 256

// estructura con los metadatos del fichero y la clave de sesion cifrada
// esto es lo primero que el cliente envia al servidor
typedef struct {
    uint64_t  longitud_fichero;                  // tamano del fichero en bytes
    char      nombre_fichero[MAX_NOMBRE];        // nombre del fichero
    char      fecha_hora[20];                    // formato: "YYYY-MM-DD HH:MM:SS"
    uint8_t   clave_sesion_cifrada[TAM_CLAVE_CIFRADA]; // clave AES cifrada con RSA publica del server
    uint8_t   iv[TAM_IV];                        // iv para AES-CBC, se genera en el cliente
    int       len_clave_cifrada;                 // longitud real de la clave cifrada (puede variar)
} MetadatosFichero;

// respuesta del servidor al cliente tras recibir los metadatos
typedef struct {
    int aceptado; // 1 si el servidor acepta la transferencia, 0 si no
} RespuestaServidor;

#endif // COMMON_H