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

// pragma pack(1) elimina el padding que gcc puede insertar entre campos
// sin esto sizeof(MetadatosFichero) puede ser 564 en vez de 560
// y la serializacion cliente<->servidor se rompe
#pragma pack(push, 1)
typedef struct {
    uint64_t  longitud_fichero;                   // 8 bytes
    char      nombre_fichero[MAX_NOMBRE];         // 256 bytes
    char      fecha_hora[20];                     // 20 bytes
    uint8_t   clave_sesion_cifrada[TAM_CLAVE_CIFRADA]; // 256 bytes
    uint8_t   iv[TAM_IV];                         // 16 bytes
    int       len_clave_cifrada;                  // 4 bytes
} MetadatosFichero;                               // total: 560 bytes exactos
#pragma pack(pop)

// respuesta del servidor al cliente tras recibir los metadatos
typedef struct {
    int aceptado; // 1 si acepta, 0 si rechaza
} RespuestaServidor;

#endif // COMMON_H