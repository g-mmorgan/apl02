#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>

// cifra la clave de sesion con la clave publica RSA del servidor
// devuelve la longitud del bloque cifrado o -1 si hay error
int cifrar_clave_rsa(const char *ruta_cert_servidor,
                     const uint8_t *clave_sesion, int len_clave,
                     uint8_t *salida_cifrada);

// descifra la clave de sesion con la clave privada RSA del servidor
// devuelve la longitud de la clave descifrada o -1 si hay error
int descifrar_clave_rsa(const char *ruta_clave_privada,
                        const uint8_t *entrada_cifrada, int len_cifrada,
                        uint8_t *clave_sesion);

// cifra un buffer con AES-256-CBC usando clave e iv dados
// buf_salida debe tener espacio suficiente (len + un bloque AES de margen)
// devuelve la longitud del buffer cifrado o -1 si hay error
int cifrar_aes(const uint8_t *clave, const uint8_t *iv,
               const uint8_t *datos, int len_datos,
               uint8_t *buf_salida);

// descifra un buffer con AES-256-CBC
// devuelve la longitud del buffer descifrado o -1 si hay error
int descifrar_aes(const uint8_t *clave, const uint8_t *iv,
                  const uint8_t *datos_cifrados, int len_cifrados,
                  uint8_t *buf_salida);

#endif // CRYPTO_UTILS_H