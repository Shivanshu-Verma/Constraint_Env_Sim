// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <stdbool.h>
// #include <stdint.h>

// #include <irq.h>
// #include <libbase/uart.h>
// #include <libbase/console.h>
// #include <generated/csr.h>
// #include <wolfssl/wolfcrypt/user_settings.h>
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
// #ifdef CSR_ETHMAC_BASE
// #include <libliteeth/udp.h>
// #endif

// // static FATFS fs;//File system object to use Fatfs

// #ifdef min
// #undef min
// #endif

// #ifdef max
// #undef max
// #endif

// #ifndef DTLS_CLIENT_PORT
// #define DTLS_CLIENT_PORT        60000
// #endif

// #ifndef DTLS_SERVER_PORT
// #define DTLS_SERVER_PORT        5684
// #endif

// #ifdef CSR_ETHMAC_BASE
// #ifndef DTLS_LOCAL_MAC0
// #define DTLS_LOCAL_MAC0 0xaa
// #define DTLS_LOCAL_MAC1 0xb6
// #define DTLS_LOCAL_MAC2 0x24
// #define DTLS_LOCAL_MAC3 0x69
// #define DTLS_LOCAL_MAC4 0x77
// #define DTLS_LOCAL_MAC5 0x21
// #endif

// #ifndef DTLS_LOCAL_IP0
// #define DTLS_LOCAL_IP0  192
// #define DTLS_LOCAL_IP1  168
// #define DTLS_LOCAL_IP2  1
// #define DTLS_LOCAL_IP3  50
// #endif

// #ifndef DTLS_REMOTE_IP0
// #define DTLS_REMOTE_IP0 192
// #define DTLS_REMOTE_IP1 168
// #define DTLS_REMOTE_IP2 1
// #define DTLS_REMOTE_IP3 100
// #endif
// #endif

// #ifdef CSR_ETHMAC_BASE
// static const uint8_t kDtlsLocalMac[6] = {
//     DTLS_LOCAL_MAC0, DTLS_LOCAL_MAC1, DTLS_LOCAL_MAC2,
//     DTLS_LOCAL_MAC3, DTLS_LOCAL_MAC4, DTLS_LOCAL_MAC5,
// };

// static const uint32_t kDtlsLocalIp =
//     IPTOINT(DTLS_LOCAL_IP0, DTLS_LOCAL_IP1, DTLS_LOCAL_IP2, DTLS_LOCAL_IP3);
// static const uint32_t kDtlsRemoteIp =
//     IPTOINT(DTLS_REMOTE_IP0, DTLS_REMOTE_IP1, DTLS_REMOTE_IP2, DTLS_REMOTE_IP3);
// #endif

// #ifdef CSR_ETHMAC_BASE
// typedef struct {
//     unsigned long send_calls;
//     unsigned long arp_failures;
//     unsigned long udp_send_failures;
//     unsigned long last_send_len;
//     int last_send_status;
// } DtlsDebugStats;

// static DtlsDebugStats g_dtls_debug_stats;

// static void dtls_debug_dump_bytes(const char* label, const uint8_t* data, int len)
// {
//     if (!data || len <= 0)
//         return;
//     const int preview = len < 16 ? len : 16;
//     printf("%s (%d bytes):", label, len);
//     for (int i = 0; i < preview; ++i)
//         printf(" %02x", data[i]);
//     if (len > preview)
//         printf(" ...");
//     printf("\n");
// }

// static void dtls_debug_print_stats(void)
// {
//     printf("DTLS debug: sends=%lu arp_fail=%lu udp_fail=%lu last_len=%lu last_status=%d\n",
//         g_dtls_debug_stats.send_calls,
//         g_dtls_debug_stats.arp_failures,
//         g_dtls_debug_stats.udp_send_failures,
//         g_dtls_debug_stats.last_send_len,
//         g_dtls_debug_stats.last_send_status);
// }
// #endif

// extern void busy_wait(unsigned int ms);
// extern void busy_wait_us(unsigned int us);



// //-----------------------------Wolf required stubs--------------------------------------
// #include <wolfssl/wolfcrypt/types.h>

// /* Replace this with a real HW entropy source (TRNG on FPGA if available) */
// int CustomRngGenerateBlock(byte *output, word32 sz) {
//     for (word32 i = 0; i < sz; i++) {
//         output[i] = (byte)(i * 37 + 123); // placeholder (NOT SECURE!)
//     }
//     return 0;
// }

// #include <sys/time.h>
// #include <time.h>

// static inline uint64_t dtls_read_cycle_counter(void)
// {
// #if __riscv_xlen == 32
//     uint32_t hi0, hi1, lo;
//     do {
//         __asm__ volatile ("rdcycleh %0" : "=r"(hi0));
//         __asm__ volatile ("rdcycle %0" : "=r"(lo));
//         __asm__ volatile ("rdcycleh %0" : "=r"(hi1));
//     } while (hi0 != hi1);
//     return ((uint64_t)hi1 << 32) | lo;
// #else
//     uint64_t value;
//     __asm__ volatile ("rdcycle %0" : "=r"(value));
//     return value;
// #endif
// }

// static inline uint64_t dtls_cycles_to_us(uint64_t cycles)
// {
//     const uint64_t freq = CONFIG_CLOCK_FREQUENCY;
//     const uint64_t seconds = cycles / freq;
//     const uint64_t remainder = cycles % freq;
//     uint64_t usec = seconds * 1000000ULL;
//     usec += (remainder * 1000000ULL) / freq;
//     return usec;
// }

// /* Provide a monotonic time source backed by the RISC-V cycle counter */
// int gettimeofday(struct timeval* tv, void* tz)
// {
//     (void)tz;
//     if (tv) {
//         uint64_t usec = dtls_cycles_to_us(dtls_read_cycle_counter());
//         tv->tv_sec = usec / 1000000ULL;
//         tv->tv_usec = usec % 1000000ULL;
//     }
//     return 0;
// }
// #define DTLS_PACKET_MAX            1600
// #define DTLS_PACKET_QUEUE_DEPTH      16

// typedef struct {
//     int len;
//     byte data[DTLS_PACKET_MAX];
// } DtlsPacket;

// typedef struct {
//     DtlsPacket packets[DTLS_PACKET_QUEUE_DEPTH];
//     int head;
//     int tail;
//     int count;
// } DtlsPacketQueue;

// typedef struct {
//     DtlsPacketQueue queue;
//     uint32_t remote_ip;
//     uint16_t remote_port;
//     uint16_t local_port;
//     bool arp_ready;
//     bool arp_probe_pending;
//     uint32_t last_arp_request_ms;
//     uint32_t last_arp_refresh_ms;
// } DtlsUdpTransport;

// static uint32_t g_dtls_timebase_ms = 0;
// static const uint32_t kDtlsArpTtlMs = 5000;
// static const uint32_t kDtlsArpRetryMs = 500;

// static inline uint32_t dtls_now_ms(void)
// {
//     return g_dtls_timebase_ms;
// }

// static inline void dtls_advance_ms(uint32_t delta)
// {
//     g_dtls_timebase_ms += delta;
// }

// static inline void dtls_reset_timebase(void)
// {
//     g_dtls_timebase_ms = 0;
// }

// static void dtls_queue_init(DtlsPacketQueue* q)
// {
//     q->head = 0;
//     q->tail = 0;
//     q->count = 0;
// }

// static int dtls_queue_push(DtlsPacketQueue* q, const byte* data, int len)
// {
//     if (len > DTLS_PACKET_MAX)
//         return WOLFSSL_CBIO_ERR_GENERAL;
//     if (q->count == DTLS_PACKET_QUEUE_DEPTH)
//         return WOLFSSL_CBIO_ERR_WANT_WRITE;

//     DtlsPacket* pkt = &q->packets[q->tail];
//     memcpy(pkt->data, data, len);
//     pkt->len = len;
//     q->tail = (q->tail + 1) % DTLS_PACKET_QUEUE_DEPTH;
//     q->count++;
//     return len;
// }

// static int dtls_queue_pop(DtlsPacketQueue* q, byte* data, int max_len)
// {
//     if (q->count == 0)
//         return WOLFSSL_CBIO_ERR_WANT_READ;

//     DtlsPacket* pkt = &q->packets[q->head];
//     if (pkt->len > max_len)
//         return WOLFSSL_CBIO_ERR_GENERAL;

//     memcpy(data, pkt->data, pkt->len);
//     int len = pkt->len;
//     q->head = (q->head + 1) % DTLS_PACKET_QUEUE_DEPTH;
//     q->count--;
//     return len;
// }
// #ifdef CSR_ETHMAC_BASE
// static DtlsUdpTransport* g_udp_transport = NULL;

// static inline bool dtls_time_elapsed(uint32_t now, uint32_t then, uint32_t window)
// {
//     return (uint32_t)(now - then) >= window;
// }

// static inline uint8_t dtls_ip_octet(uint32_t ip, int idx)
// {
//     return (ip >> (24 - (idx * 8))) & 0xff;
// }

// static void dtls_log_ip(const char* label, uint32_t ip)
// {
//     printf("%s %d.%d.%d.%d\n", label,
//         dtls_ip_octet(ip, 0), dtls_ip_octet(ip, 1),
//         dtls_ip_octet(ip, 2), dtls_ip_octet(ip, 3));
// }

// static void dtls_prime_network(DtlsUdpTransport* transport)
// {
//     if (!transport)
//         return;

//     printf("Priming network path towards remote host...\n");
//     int arp_ok = udp_arp_resolve(transport->remote_ip);
//     printf("Initial ARP %s\n", arp_ok ? "completed" : "failed (no reply)" );

//     if (arp_ok) {
//     transport->arp_ready = true;
//     transport->arp_probe_pending = false;
//     transport->last_arp_refresh_ms = dtls_now_ms();
//     transport->last_arp_request_ms = dtls_now_ms();
//         int ping_status = send_ping(transport->remote_ip, 8);
//         if (ping_status == 0) {
//             printf("Ping round-trip succeeded\n");
//         } else if (ping_status == -2) {
//             printf("Ping transmitted but no reply observed\n");
//         } else {
//             printf("Ping transmit error %d\n", ping_status);
//         }
//     } else {
//         transport->arp_ready = false;
//         transport->arp_probe_pending = true;
//         transport->last_arp_request_ms = dtls_now_ms() - kDtlsArpRetryMs;
//         printf("Unable to resolve remote MAC yet; DTLS will keep retrying during handshake\n");
//     }
// }

// static void dtls_poll_network(unsigned iterations)
// {
//     const unsigned ticks = iterations ? iterations : 1;
//     for (unsigned i = 0; i < iterations; ++i)
//         udp_service();

//     dtls_advance_ms(ticks);

//     if (!g_udp_transport)
//         return;

//     DtlsUdpTransport* transport = g_udp_transport;
//     const uint32_t now = dtls_now_ms();
//     if (transport->arp_ready && dtls_time_elapsed(now, transport->last_arp_refresh_ms, kDtlsArpTtlMs)) {
//         transport->arp_ready = false;
//         transport->arp_probe_pending = true;
//         transport->last_arp_request_ms = now - kDtlsArpRetryMs;
//     }

//     if ((transport->arp_probe_pending || !transport->arp_ready) &&
//         dtls_time_elapsed(now, transport->last_arp_request_ms, kDtlsArpRetryMs)) {
//         int resolved = udp_arp_resolve(transport->remote_ip);
//         transport->last_arp_request_ms = now;
//         if (resolved) {
//             transport->arp_ready = true;
//             transport->arp_probe_pending = false;
//             transport->last_arp_refresh_ms = now;
//             printf("ARP refreshed successfully\n");
//         }
//     }
// }

// static void dtls_udp_rx_callback(uint32_t src_ip, uint16_t src_port,
//                                  uint16_t dst_port, void* data, uint32_t length)
// {
//     (void)src_ip;
//     if (!g_udp_transport)
//         return;

//     if (dst_port != g_udp_transport->local_port)
//         return;
//     if (src_port != g_udp_transport->remote_port)
//         return;

//     if (dtls_queue_push(&g_udp_transport->queue, (const byte*)data, (int)length) < 0)
//         printf("DTLS RX queue full, dropping packet\n");
// }

// static int dtls_udp_init(DtlsUdpTransport* transport)
// {
//     if (!transport)
//         return -1;

//     dtls_queue_init(&transport->queue);
//     transport->local_port = DTLS_CLIENT_PORT;
//     transport->remote_port = DTLS_SERVER_PORT;
//     transport->remote_ip = kDtlsRemoteIp;
//     transport->arp_ready = false;
//     transport->arp_probe_pending = true;
//     transport->last_arp_request_ms = dtls_now_ms() - kDtlsArpRetryMs;
//     transport->last_arp_refresh_ms = 0;

//     eth_init();
//     udp_start(kDtlsLocalMac, kDtlsLocalIp);
//     udp_set_callback(dtls_udp_rx_callback);
//     g_udp_transport = transport;
//     memset(&g_dtls_debug_stats, 0, sizeof(g_dtls_debug_stats));

//     dtls_log_ip("Local IP:", kDtlsLocalIp);
//     dtls_log_ip("Remote IP:", transport->remote_ip);
//     printf("DTLS UDP ports: %u -> %u\n", transport->local_port, transport->remote_port);

//     dtls_prime_network(transport);

//     return 0;
// }

// static int dtls_udp_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
// {
//     (void)ssl;
//     DtlsUdpTransport* transport = (DtlsUdpTransport*)ctx;
//     if (!transport)
//         return WOLFSSL_CBIO_ERR_GENERAL;

//     if (sz > UDP_BUFSIZE)
//         return WOLFSSL_CBIO_ERR_GENERAL;

//     g_dtls_debug_stats.send_calls++;
//     g_dtls_debug_stats.last_send_len = (unsigned long)sz;

//     const uint32_t now = dtls_now_ms();
//     if (!(transport->arp_ready && !dtls_time_elapsed(now, transport->last_arp_refresh_ms, kDtlsArpTtlMs))) {
//         transport->arp_ready = false;
//         transport->arp_probe_pending = true;
//         if ((uint32_t)(now - transport->last_arp_request_ms) >= 100) {
//             (void)udp_arp_resolve(transport->remote_ip);
//             transport->last_arp_request_ms = now;
//         }
//         g_dtls_debug_stats.arp_failures++;
//         g_dtls_debug_stats.last_send_status = WOLFSSL_CBIO_ERR_WANT_WRITE;
//         if ((g_dtls_debug_stats.arp_failures & 0x7) == 1)
//             printf("dtls_udp_send: ARP unresolved (attempt %lu)\n", g_dtls_debug_stats.arp_failures);
//         return WOLFSSL_CBIO_ERR_WANT_WRITE;
//     }

//     uint8_t* payload = (uint8_t*)udp_get_tx_buffer();
//     if (!payload)
//         return WOLFSSL_CBIO_ERR_GENERAL;

//     memcpy(payload, buf, sz);
//     if (!udp_send(transport->local_port, transport->remote_port, (uint32_t)sz)) {
//         g_dtls_debug_stats.udp_send_failures++;
//         g_dtls_debug_stats.last_send_status = WOLFSSL_CBIO_ERR_WANT_WRITE;
//         printf("dtls_udp_send: udp_send failed (failures=%lu)\n", g_dtls_debug_stats.udp_send_failures);
//         return WOLFSSL_CBIO_ERR_WANT_WRITE;
//     }

//     transport->last_arp_refresh_ms = now;
//     dtls_poll_network(1);

//     g_dtls_debug_stats.last_send_status = sz;
//     if (g_dtls_debug_stats.send_calls <= 3)
//         dtls_debug_dump_bytes("DTLS TX", (const uint8_t*)buf, sz);

//     return sz;
// }

// static int dtls_udp_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
// {
//     (void)ssl;
//     DtlsUdpTransport* transport = (DtlsUdpTransport*)ctx;
//     if (!transport)
//         return WOLFSSL_CBIO_ERR_GENERAL;

//     int ret = dtls_queue_pop(&transport->queue, (byte*)buf, sz);
//     if (ret == WOLFSSL_CBIO_ERR_WANT_READ)
//         dtls_poll_network(1);
//     return ret;
// }
// #endif

// static const unsigned char kDtlsPskKey[] = {
//     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
// };
// #define DTLS_PSK_IDENTITY "litex-client"

// static unsigned int dtls_client_psk_cb(WOLFSSL* ssl, const char* hint,
//                                        char* identity, unsigned int id_max_len,
//                                        unsigned char* key, unsigned int key_max_len)
// {
//     (void)ssl;
//     (void)hint;
//     const char* ident = DTLS_PSK_IDENTITY;
//     unsigned int ident_len = (unsigned int)strlen(ident);
//     if (ident_len > id_max_len || sizeof(kDtlsPskKey) > key_max_len)
//         return 0;
//     memcpy(identity, ident, ident_len);
//     memcpy(key, kDtlsPskKey, sizeof(kDtlsPskKey));
//     return sizeof(kDtlsPskKey);
// }

// static unsigned int __attribute__((unused)) dtls_server_psk_cb(WOLFSSL* ssl, const char* identity,
//                                        unsigned char* key, unsigned int key_max_len)
// {
//     (void)ssl;
//     if (identity == NULL)
//         return 0;
//     if (strncmp(identity, DTLS_PSK_IDENTITY, strlen(DTLS_PSK_IDENTITY)) != 0)
//         return 0;
//     if (sizeof(kDtlsPskKey) > key_max_len)
//         return 0;
//     memcpy(key, kDtlsPskKey, sizeof(kDtlsPskKey));
//     return sizeof(kDtlsPskKey);
// }

// static int run_dtls_client_demo(void)
// {
// #ifndef CSR_ETHMAC_BASE
//     printf("\n=== DTLS 1.3 PSK Demo ===\n");
//     printf("Ethernet MAC not included in this build. Re-run litex_sim with --with-ethernet.\n");
//     return -1;
// #else
//     int ret = -1;
//     WOLFSSL_CTX* client_ctx = NULL;
//     WOLFSSL* client = NULL;
//     DtlsUdpTransport transport;
//     bool client_ready = false;
//     const char client_msg[] = "ping from LiteX DTLS client";
//     char rx_buffer[128];

//     printf("\n=== DTLS 1.3 PSK Demo ===\n");
//     printf("Waiting for DTLS server at %d.%d.%d.%d:%u...\n",
//         dtls_ip_octet(kDtlsRemoteIp, 0), dtls_ip_octet(kDtlsRemoteIp, 1),
//         dtls_ip_octet(kDtlsRemoteIp, 2), dtls_ip_octet(kDtlsRemoteIp, 3),
//         DTLS_SERVER_PORT);

//     if (dtls_udp_init(&transport) != 0) {
//         printf("Failed to initialize UDP transport\n");
//         return -1;
//     }

//     wolfSSL_Init();
//     wolfSSL_Debugging_ON();

//     client_ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
//     if (!client_ctx) {
//         printf("Failed to create DTLS client context\n");
//         goto cleanup;
//     }

//     wolfSSL_CTX_set_psk_client_callback(client_ctx, dtls_client_psk_cb);
//     wolfSSL_CTX_set_cipher_list(client_ctx, "TLS13-AES128-GCM-SHA256");
//     wolfSSL_SetIORecv(client_ctx, dtls_udp_recv);
//     wolfSSL_SetIOSend(client_ctx, dtls_udp_send);

//     client = wolfSSL_new(client_ctx);
//     if (!client) {
//         printf("Failed to create DTLS client session\n");
//         goto cleanup;
//     }

//     wolfSSL_SetIOReadCtx(client, &transport);
//     wolfSSL_SetIOWriteCtx(client, &transport);
//     wolfSSL_set_using_nonblock(client, 1);

//     const int max_loops = 2000;
//     printf("Starting DTLS handshake loop (max %d iterations)\n", max_loops);
//     for (int i = 0; i < max_loops && !client_ready; ++i) {
//         dtls_poll_network(2);
//         int cres = wolfSSL_connect(client);
//         if (cres == WOLFSSL_SUCCESS) {
//             client_ready = true;
//             printf("Client handshake complete\n");
//             break;
//         }
//         int err = wolfSSL_get_error(client, cres);
//         if (i < 5)
//             printf("wolfSSL_connect iter=%d result=%d err=%d\n", i, cres, err);
//         if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
//             if ((i % 50) == 0)
//                 printf("Handshake waiting loop=%d queue=%d send=%lu arp_fail=%lu last=%d arp_ready=%d\n",
//                     i, transport.queue.count,
//                     g_dtls_debug_stats.send_calls,
//                     g_dtls_debug_stats.arp_failures,
//                     g_dtls_debug_stats.last_send_status,
//                     transport.arp_ready);
//             dtls_poll_network(4);
//             busy_wait_us(1000);
//             dtls_advance_ms(1);
//             continue;
//         }
//         printf("Client handshake error %d\n", err);
//         dtls_debug_print_stats();
//         goto cleanup;
//     }

//     if (!client_ready) {
//         printf("Handshake timed out waiting for server\n");
//         dtls_debug_print_stats();
//         goto cleanup;
//     }

//     int write_ret = wolfSSL_write(client, client_msg, sizeof(client_msg));
//     if (write_ret != (int)sizeof(client_msg)) {
//         int err = wolfSSL_get_error(client, write_ret);
//         printf("Client write error %d\n", err);
//         dtls_debug_print_stats();
//         goto cleanup;
//     }

//     while (true) {
//         int read_ret = wolfSSL_read(client, rx_buffer, sizeof(rx_buffer));
//         if (read_ret > 0) {
//             printf("Client received: %.*s\n", read_ret, rx_buffer);
//             break;
//         }
//         int err = wolfSSL_get_error(client, read_ret);
//         if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
//             dtls_poll_network(4);
//             continue;
//         }
//         printf("Client read error %d\n", err);
//         dtls_debug_print_stats();
//         goto cleanup;
//     }

//     printf("DTLS secure message exchange complete\n");
//     ret = 0;

// cleanup:
//     if (client)
//         wolfSSL_free(client);
//     if (client_ctx)
//         wolfSSL_CTX_free(client_ctx);
//     wolfSSL_Cleanup();
//     udp_set_callback(NULL);
//     g_udp_transport = NULL;

//     return ret;
// #endif
// }

// int main(void)
// {
// #ifdef CONFIG_CPU_HAS_INTERRUPT
// 	irq_setmask(0);
// 	irq_setie(1);
// #endif
// 	uart_init();

//     if (run_dtls_client_demo() == 0) {
//         printf("DTLS demo finished successfully.\n");
//     } else {
//         printf("DTLS demo failed.\n");
//     }

//     return 0;
// }






// //     /* Initialize SDCard */
// //     // sdcard_init();
//     // spisdcard_init();
// //     printf("sdcard_init() done\n");

// //     /* Bind FatFS to SPI backend */
//     // fatfs_set_ops_spisdcard();
// //     printf("fatfs_set_ops_sdcard() done\n");
    
// //     /* Mount filesystem */
// //     FRESULT fr = f_mount(&fs, "", 1);  //MS-DOS partition table + FAT32 Filesystem
// //     printf("f_mount -> %d\n", fr);
// //     if (fr != FR_OK) {
// //         printf("mount failed\n");
// //         return 1;
// //     }

// //     FIL file;
// //     UINT bytes=0;

// //     /* PHASE 1 — READ existing file */
// //     printf("\n[PHASE 1] Opening test.txt for READ...\n");
// //     fr = f_open(&file, "Work.txt", FA_READ | FA_OPEN_EXISTING);
// //     printf("[PHASE 1] f_open -> %d\n", fr);
// //     if (fr != FR_OK) return 1;

// //     static char buf[4096];
// //     memset(buf, 0, sizeof(buf));

// //     fr = f_read(&file, buf, sizeof(buf)-1, &bytes);
// //     printf("[PHASE 1] f_read -> %d, bytes=%u\n", fr, bytes);
// //     printf("[PHASE 1] Contents BEFORE write:\n%s\n", buf);

// //     f_close(&file);
// //     bytes=0;

// //     /* PHASE 2 — file write */
// //     printf("\n[PHASE 2] Opening test.txt for WRITE + TRUNCATE...\n");
// //     fr = f_open(&file, "Work.txt", FA_WRITE | FA_OPEN_EXISTING);
// //     printf("[PHASE 2] f_open -> %d\n", fr);
// //     if (fr != FR_OK) return 1;

// //     f_lseek(&file, f_size(&file));
// //     // f_truncate(&file); 

// //     const char *msg = "\nHELLO TO THE WORLD\n";
// //     fr = f_write(&file, msg, strlen(msg), &bytes); 
// //     printf("[PHASE 2] f_write -> %d, bytes=%u\n", fr, bytes);
 
// //     f_close(&file);// IT FAILS HERE
// //     bytes=0;

// //     /* PHASE 3 — Read again */
// //     printf("\n[PHASE 3] Opening test.txt for READ again...\n");
// //     fr = f_open(&file, "Work.txt", FA_READ | FA_OPEN_EXISTING);
// //     printf("[PHASE 3] f_open -> %d\n", fr);
// //     if (fr != FR_OK) return 1;

// //     memset(buf, 0, sizeof(buf));

// //     fr = f_read(&file, buf, sizeof(buf)-1, &bytes);
// //     printf("[PHASE 3] f_read -> %d, bytes=%u\n", fr, bytes);
// //     printf("[PHASE 3] Contents AFTER write:\n%s\n", buf);

// //     f_close(&file);

// //     printf("\n=== SD TEST COMPLETE ===\n");

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <irq.h>
#include <libbase/uart.h>
#include <libbase/console.h>
#include <generated/csr.h>

#ifdef CSR_ETHMAC_BASE
#include <libliteeth/udp.h>
#endif

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#ifndef PING_TARGET_HOSTNAME   ""
#define PING_TARGET_HOSTNAME   "192.168.1.100"
#endif

#ifndef PING_PAYLOAD_LENGTH
#define PING_PAYLOAD_LENGTH    8
#endif

#ifndef PING_ATTEMPTS
#define PING_ATTEMPTS          4
#endif

#ifdef CSR_ETHMAC_BASE
#ifndef PING_LOCAL_MAC0
#define PING_LOCAL_MAC0 0xaa
#define PING_LOCAL_MAC1 0xb6
#define PING_LOCAL_MAC2 0x24
#define PING_LOCAL_MAC3 0x69
#define PING_LOCAL_MAC4 0x77
#define PING_LOCAL_MAC5 0x21
#endif

#ifndef PING_LOCAL_IP0
#define PING_LOCAL_IP0  192
#define PING_LOCAL_IP1  168
#define PING_LOCAL_IP2  1
#define PING_LOCAL_IP3  50
#endif

static const uint8_t kLocalMac[6] = {
	PING_LOCAL_MAC0, PING_LOCAL_MAC1, PING_LOCAL_MAC2,
	PING_LOCAL_MAC3, PING_LOCAL_MAC4, PING_LOCAL_MAC5,
};

static const uint32_t kLocalIp = IPTOINT(
	PING_LOCAL_IP0, PING_LOCAL_IP1, PING_LOCAL_IP2, PING_LOCAL_IP3);
#endif

static void print_banner(void)
{
	printf("\n=== LiteX Ping Demo ===\n");
	printf("Target host string : %s\n", PING_TARGET_HOSTNAME);
#ifdef CSR_ETHMAC_BASE
	printf("Local interface     : %d.%d.%d.%d\n",
		PING_LOCAL_IP0, PING_LOCAL_IP1, PING_LOCAL_IP2, PING_LOCAL_IP3);
#endif
	printf("Payload size        : %d bytes\n", PING_PAYLOAD_LENGTH);
	printf("Max attempts        : %d\n\n", PING_ATTEMPTS);
}

#ifdef CSR_ETHMAC_BASE
static inline uint8_t ip_octet(uint32_t ip, int index)
{
	return (ip >> (24 - (index * 8))) & 0xff;
}

static void print_ip(const char* label, uint32_t ip)
{
	printf("%s %d.%d.%d.%d\n", label,
		ip_octet(ip, 0), ip_octet(ip, 1), ip_octet(ip, 2), ip_octet(ip, 3));
}

static bool parse_ipv4_string(const char* text, uint32_t* out_ip)
{
	if (!text || !out_ip)
		return false;

	int octets[4] = {0};
	int octet_index = 0;
	int accum = -1;

	for (const char* p = text; ; ++p) {
		char c = *p;
		if (c >= '0' && c <= '9') {
			if (accum < 0)
				accum = 0;
			accum = accum * 10 + (c - '0');
			if (accum > 255)
				return false;
			continue;
		}

		if (c == '.' || c == '\0') {
			if (accum < 0 || octet_index >= 4)
				return false;
			octets[octet_index++] = accum;
			accum = -1;
			if (c == '\0')
				break;
			continue;
		}

		return false; /* unsupported character */
	}

	if (octet_index != 4)
		return false;

	*out_ip = IPTOINT(octets[0], octets[1], octets[2], octets[3]);
	return true;
}

static void pump_network(unsigned iterations)
{
	for (unsigned i = 0; i < iterations; ++i)
		udp_service();
}

static int run_ping_demo(void)
{
	print_banner();

	uint32_t target_ip;
	if (!parse_ipv4_string(PING_TARGET_HOSTNAME, &target_ip)) {
		printf("Error: PING_TARGET_HOSTNAME must be an IPv4 address in dotted-decimal form.\n");
		return -1;
	}

	eth_init();
	udp_start(kLocalMac, kLocalIp);
	udp_set_callback(NULL);

	print_ip("Local IP:", kLocalIp);
	print_ip("Target IP:", target_ip);

	printf("Resolving ARP...");
	if (!udp_arp_resolve(target_ip)) {
		printf(" failed (no reply).\n");
		return -1;
	}
	printf(" done.\n");

	for (int attempt = 1; attempt <= PING_ATTEMPTS; ++attempt) {
		printf("Ping attempt %d/%d...\n", attempt, PING_ATTEMPTS);
		int status = send_ping(target_ip, PING_PAYLOAD_LENGTH);
		pump_network(32);

		if (status == 0) {
			printf("Reply received from %d.%d.%d.%d\n",
				ip_octet(target_ip, 0), ip_octet(target_ip, 1),
				ip_octet(target_ip, 2), ip_octet(target_ip, 3));
			return 0;
		}

		if (status == -2)
			printf("No reply observed (timeout).\n");
		else
			printf("Ping transmit error %d.\n", status);
	}

	printf("All ping attempts failed.\n");
	return -1;
}

#else /* !CSR_ETHMAC_BASE */
static int run_ping_demo(void)
{
	print_banner();
	printf("Error: This build does not include an Ethernet MAC. Re-run litex_sim with --with-ethernet.\n");
	return -1;
}
#endif

int main(void)
{
#ifdef CONFIG_CPU_HAS_INTERRUPT
	irq_setmask(0);
	irq_setie(1);
#endif
	uart_init();

	if (run_ping_demo() == 0)
		printf("Ping demo finished successfully.\n");
	else
		printf("Ping demo failed.\n");

	return 0;
}