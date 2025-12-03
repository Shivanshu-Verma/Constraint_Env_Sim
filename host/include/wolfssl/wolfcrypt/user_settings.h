#ifndef HOST_USER_SETTINGS_H
#define HOST_USER_SETTINGS_H

/* Enable the DTLS/TLS 1.3 feature set used by the LiteX demo */
#define WOLFSSL_TLS13
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_DTLS_CH_FRAG
#define HAVE_TLS_EXTENSIONS
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_CERT_VERIFY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_PSK
#define HAVE_HKDF

/* Cryptography primitives */
#define WOLFSSL_SP_MATH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_RSA
#define HAVE_ECC
#define HAVE_ECC256
#define HAVE_CURVE25519
#define HAVE_X25519
#define HAVE_ED25519
#define HAVE_AESGCM
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* Keep the stack small but allow full socket + time support on host */
/* (WolfSSL defaults provide BSD sockets + time, so no extra defines needed) */

#endif /* HOST_USER_SETTINGS_H */
