#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define DEFAULT_LISTEN_IP   "192.168.1.100"
#define DEFAULT_LISTEN_PORT 5684
#define DTLS_PSK_IDENTITY   "litex-client"

static const unsigned char kPskKey[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--listen <ip>] [--port <port>] [--debug]\n"
        "\n"
        "Defaults: --listen %s --port %d\n",
        prog, DEFAULT_LISTEN_IP, DEFAULT_LISTEN_PORT);
}

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static unsigned int server_psk_cb(WOLFSSL *ssl, const char *identity,
                                  unsigned char *key, unsigned int key_max_len)
{
    (void)ssl;
    if (!identity || strcmp(identity, DTLS_PSK_IDENTITY) != 0)
        return 0;
    if (sizeof(kPskKey) > key_max_len)
        return 0;
    memcpy(key, kPskKey, sizeof(kPskKey));
    return sizeof(kPskKey);
}

static int open_udp_socket(const char *ip, uint16_t port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        die("socket");

    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        die("setsockopt");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_aton(ip, &addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind");

    return sock;
}

static void wait_for_client(int sock, struct sockaddr_in *client_addr)
{
    uint8_t scratch[1500];
    socklen_t addr_len = sizeof(*client_addr);

    while (true) {
        ssize_t n = recvfrom(sock, scratch, sizeof(scratch), MSG_PEEK,
                             (struct sockaddr *)client_addr, &addr_len);
        if (n >= 0)
            break;
        if (errno == EINTR)
            continue;
        die("recvfrom");
    }

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, addr_str, sizeof(addr_str));
    printf("Received ClientHello from %s:%u\n", addr_str, ntohs(client_addr->sin_port));
}

int main(int argc, char **argv)
{
    const char *listen_ip = DEFAULT_LISTEN_IP;
    uint16_t listen_port = DEFAULT_LISTEN_PORT;
    bool enable_debug = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--listen") == 0 && (i + 1) < argc) {
            listen_ip = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && (i + 1) < argc) {
            listen_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--debug") == 0) {
            enable_debug = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    printf("DTLS server listening on %s:%u\n", listen_ip, listen_port);

    wolfSSL_Init();
    if (enable_debug)
        wolfSSL_Debugging_ON();

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create WolfSSL context\n");
        return EXIT_FAILURE;
    }

    wolfSSL_CTX_set_psk_server_callback(ctx, server_psk_cb);
    if (wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256") != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to set cipher list\n");
        wolfSSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    while (true) {
        int sock = open_udp_socket(listen_ip, listen_port);
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        wait_for_client(sock, &client_addr);

        if (connect(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
            die("connect");

        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "Failed to allocate WolfSSL session\n");
            close(sock);
            break;
        }

        wolfSSL_dtls_set_peer(ssl, &client_addr, sizeof(client_addr));
        wolfSSL_set_fd(ssl, sock);

        printf("Starting DTLS handshake...\n");
        while (true) {
            int ret = wolfSSL_accept(ssl);
            if (ret == WOLFSSL_SUCCESS) {
                printf("Handshake complete.\n");
                break;
            }
            int err = wolfSSL_get_error(ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
                continue;
            fprintf(stderr, "wolfSSL_accept failed: %d\n", err);
            goto session_cleanup;
        }

        uint8_t buffer[256];
        while (true) {
            int len = wolfSSL_read(ssl, buffer, sizeof(buffer));
            if (len > 0) {
                printf("Client says: %.*s\n", len, buffer);
                break;
            }
            int err = wolfSSL_get_error(ssl, len);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
                continue;
            fprintf(stderr, "wolfSSL_read failed: %d\n", err);
            goto session_cleanup;
        }

        const char response[] = "pong from host DTLS server";
        const int response_len = sizeof(response);
        while (true) {
            int wrote = wolfSSL_write(ssl, response, response_len);
            if (wrote == response_len) {
                printf("Response sent.\n");
                break;
            }
            int err = wolfSSL_get_error(ssl, wrote);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
                continue;
            fprintf(stderr, "wolfSSL_write failed: %d\n", err);
            goto session_cleanup;
        }

        wolfSSL_shutdown(ssl);
        printf("Session finished. Waiting for next client...\n");

    session_cleanup:
        wolfSSL_free(ssl);
        close(sock);
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return EXIT_SUCCESS;
}
