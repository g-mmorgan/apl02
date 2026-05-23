#include "crypto_utils.h"

// cabeceras: X509 para certificados, BIO para E/S, EVP para claves
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// cabeceras para AES-256-CBC
#include <openssl/aes.h>

// ERR para imprimir errores de OpenSSL en formato legible
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>


//carga la clave publica RSA desde un certificado PEM
static EVP_PKEY *cargar_clave_publica_de_cert(const char *ruta_cert)
{
    // creamos el objeto BIO para leer el fichero PEM del certificado
    // BIO es la abstraccion de OpenSSL para E/S (temario pag 6)
    BIO *bio_in = BIO_new(BIO_s_file());
    if (!bio_in) {
        printf("[crypto] error al crear BIO\n");
        return NULL;
    }

    // abrimos el fichero PEM del certificado del servidor (clave publica)
    if (!BIO_read_filename(bio_in, ruta_cert)) {
        printf("[crypto] error al abrir el certificado: %s\n", ruta_cert);
        BIO_free(bio_in);
        return NULL;
    }

    // leemos el certificado X509 desde el BIO (temario pag 6-7)
    X509 *cert = PEM_read_bio_X509(bio_in, NULL, NULL, NULL);
    BIO_free(bio_in); // liberamos el BIO ya que ya no lo necesitamos
    if (!cert) {
        printf("[crypto] error al parsear el certificado X509\n");
        return NULL;
    }

    // extraemos la clave publica RSA del certificado (temario pag 8)
    // X509_get_pubkey devuelve un EVP_PKEY con la clave publica
    EVP_PKEY *clave_pub = X509_get_pubkey(cert);
    X509_free(cert); // liberamos el certificado, ya tenemos la clave
    if (!clave_pub) {
        printf("[crypto] error al extraer la clave publica del certificado\n");
        return NULL;
    }

    return clave_pub;
}

//carga la clave privada RSA desde un fichero PEM
//lectura usamos PEM_read_bio_PrivateKey con el mismo patron BIO
static EVP_PKEY *cargar_clave_privada(const char *ruta_clave_privada)
{
    // abrimos el fichero PEM de la clave privada con BIO
    BIO *bio_in = BIO_new(BIO_s_file());
    if (!bio_in) {
        printf("[crypto] error al crear BIO para clave privada\n");
        return NULL;
    }

    if (!BIO_read_filename(bio_in, ruta_clave_privada)) {
        printf("[crypto] error al abrir la clave privada: %s\n", ruta_clave_privada);
        BIO_free(bio_in);
        return NULL;
    }

    // leemos la clave privada RSA en formato PEM
    // NULL, NULL -> sin password (la clave no esta cifrada)
    EVP_PKEY *clave_priv = PEM_read_bio_PrivateKey(bio_in, NULL, NULL, NULL);
    BIO_free(bio_in);
    if (!clave_priv) {
        printf("[crypto] error al parsear la clave privada PEM\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return clave_priv;
}

// cifra la clave de sesion AES con la clave publica RSA
// del servidor (distribucion de clave hibrida, tipica en seguridad)
// usa EVP_PKEY_CTX que es la API moderna de OpenSSL para RSA-OAEP
int cifrar_clave_rsa(const char *ruta_cert_servidor,
                     const unsigned char *clave_sesion, int len_clave,
                     unsigned char *salida_cifrada)
{
    // cargamos la clave publica RSA del servidor desde su certificado PEM
    EVP_PKEY *clave_pub = cargar_clave_publica_de_cert(ruta_cert_servidor);
    if (!clave_pub) return -1;

    // creamos el contexto de operacion para cifrado con la clave publica
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(clave_pub, NULL);
    EVP_PKEY_free(clave_pub); // ya no necesitamos la clave suelta
    if (!ctx) {
        printf("[crypto] error al crear contexto EVP_PKEY_CTX\n");
        return -1;
    }

    // inicializamos el contexto para cifrado asimetrico
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        printf("[crypto] error en EVP_PKEY_encrypt_init\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // configuramos padding OAEP con SHA-256 (el mas seguro para cifrar claves)
    // OAEP es el padding recomendado para RSA segun PKCS#1 v2
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        printf("[crypto] error al configurar padding OAEP\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // primera llamada con salida NULL para obtener el tamano del bloque cifrado
    size_t len_salida = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &len_salida,
                         clave_sesion, (size_t)len_clave) <= 0) {
        printf("[crypto] error al calcular tamano del cifrado RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // segunda llamada con el buffer de salida para hacer el cifrado real
    if (EVP_PKEY_encrypt(ctx, salida_cifrada, &len_salida,
                         clave_sesion, (size_t)len_clave) <= 0) {
        printf("[crypto] error al cifrar con RSA\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return (int)len_salida; // devolvemos la longitud del bloque cifrado
}

// descifra la clave de sesion con la clave privada RSA
// el servidor usa esto para recuperar la clave AES que mando el cliente
int descifrar_clave_rsa(const char *ruta_clave_privada,
                        const unsigned char *entrada_cifrada, int len_cifrada,
                        unsigned char *clave_sesion)
{
    // cargamos la clave privada RSA del servidor desde su fichero PEM
    EVP_PKEY *clave_priv = cargar_clave_privada(ruta_clave_privada);
    if (!clave_priv) return -1;

    // creamos el contexto de operacion para descifrado con la clave privada
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(clave_priv, NULL);
    EVP_PKEY_free(clave_priv);
    if (!ctx) {
        printf("[crypto] error al crear contexto para descifrado RSA\n");
        return -1;
    }

    // inicializamos para descifrado
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        printf("[crypto] error en EVP_PKEY_decrypt_init\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // mismo padding OAEP que se uso en el cifrado (deben coincidir)
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        printf("[crypto] error al configurar padding OAEP en descifrado\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // primera llamada para obtener la longitud del resultado descifrado
    size_t len_salida = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &len_salida,
                         entrada_cifrada, (size_t)len_cifrada) <= 0) {
        printf("[crypto] error al calcular tamano del descifrado RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // descifrado real de la clave de sesion
    if (EVP_PKEY_decrypt(ctx, clave_sesion, &len_salida,
                         entrada_cifrada, (size_t)len_cifrada) <= 0) {
        printf("[crypto] error al descifrar con RSA\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return (int)len_salida; // longitud de la clave descifrada (deberia ser 32)
}


// cifra un buffer con AES-256-CBC usando la clave e IV dados
// usamos la API EVP de OpenSSL que es la forma moderna y recomendada
// el buffer de salida debe tener espacio para len_datos + AES_BLOCK_SIZE

int cifrar_aes(const unsigned char *clave, const unsigned char *iv,
               const unsigned char *datos, int len_datos,
               unsigned char *buf_salida)
{
    // EVP_CIPHER_CTX es el contexto de cifrado simetrico en OpenSSL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("[crypto] error al crear contexto AES\n");
        return -1;
    }

    // inicializamos cifrado AES-256-CBC: clave de 256 bits, modo CBC con IV
    // AES_256_CBC -> bloque de 16 bytes, clave de 32 bytes
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv) != 1) {
        printf("[crypto] error en EVP_EncryptInit_ex\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_parcial = 0;
    int len_total   = 0;

    // cifrado del bloque de datos (puede producir uno o varios bloques AES)
    if (EVP_EncryptUpdate(ctx, buf_salida, &len_parcial, datos, len_datos) != 1) {
        printf("[crypto] error en EVP_EncryptUpdate\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    len_total = len_parcial;

    // finalizacion: aplica el padding PKCS7 y escribe el bloque final
    // siempre hay al menos un bloque de padding (incluso si los datos son multiplo de 16)
    if (EVP_EncryptFinal_ex(ctx, buf_salida + len_total, &len_parcial) != 1) {
        printf("[crypto] error en EVP_EncryptFinal_ex\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    len_total += len_parcial;

    EVP_CIPHER_CTX_free(ctx);
    return len_total; // longitud total del bloque cifrado (siempre > len_datos)
}

// descifra un buffer cifrado con AES-256-CBC
// es la operacion inversa de cifrar_aes, usa el mismo par clave/IV
int descifrar_aes(const unsigned char *clave, const unsigned char *iv,
                  const unsigned char *datos_cifrados, int len_cifrados,
                  unsigned char *buf_salida)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("[crypto] error al crear contexto AES descifrado\n");
        return -1;
    }

    // inicializamos descifrado AES-256-CBC con la misma clave e IV del cifrado
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv) != 1) {
        printf("[crypto] error en EVP_DecryptInit_ex\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_parcial = 0;
    int len_total   = 0;

    // descifrado del bloque de datos cifrados
    if (EVP_DecryptUpdate(ctx, buf_salida, &len_parcial,
                          datos_cifrados, len_cifrados) != 1) {
        printf("[crypto] error en EVP_DecryptUpdate\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    len_total = len_parcial;

    // finalizacion: elimina el padding PKCS7 y comprueba integridad del bloque
    // si el padding no es valido (datos corrompidos o clave erronea) falla aqui
    if (EVP_DecryptFinal_ex(ctx, buf_salida + len_total, &len_parcial) != 1) {
        printf("[crypto] error en EVP_DecryptFinal_ex (padding invalido o clave incorrecta)\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    len_total += len_parcial;

    EVP_CIPHER_CTX_free(ctx);
    return len_total; // longitud de los datos originales sin padding
}