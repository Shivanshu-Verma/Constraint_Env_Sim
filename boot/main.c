#include <stdio.h>
#include <stdlib.h> 
#include <string.h>  

#include <irq.h>
#include <libbase/uart.h>
#include <libbase/console.h>
#include <generated/csr.h>
#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/ssl.h>

// static FATFS fs;//File system object to use Fatfs

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif



//-----------------------------Wolf required stubs--------------------------------------
#include <wolfssl/wolfcrypt/types.h>

/* Replace this with a real HW entropy source (TRNG on FPGA if available) */
int CustomRngGenerateBlock(byte *output, word32 sz) {
    for (word32 i = 0; i < sz; i++) {
        output[i] = (byte)(i * 37 + 123); // placeholder (NOT SECURE!)
    }
    return 0;
}

#include <sys/time.h>
#include <time.h>

/* return 0 time, the time of UNIX epoch */
int gettimeofday(struct timeval* tv, void* tz) {
    if (tv) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    return 0;
}
//-----------------------------Wolf required stubs--------------------------------------//

static int my_IO_Send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    printf("wolfSSL SEND called, size=%d\n", sz);
    return sz;  /* Claim all bytes were sent */
}

static int my_IO_Recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    printf("wolfSSL RECV called, size=%d\n", sz);
    return WOLFSSL_CBIO_ERR_WANT_READ; /* No data pending */
}

WC_RNG global_rng;
int main(void)
{
#ifdef CONFIG_CPU_HAS_INTERRUPT
	irq_setmask(0);
	irq_setie(1);
#endif
	uart_init();
    printf("\nBasic ML-KEM KEY generation TEST\n");
    
    int ret;
    wc_InitRng(&global_rng); 

    uint8_t buffer[32];
    // Generate random bytes
    ret = wc_RNG_GenerateBlock(&global_rng, buffer, 32);
    if (ret != 0) { 
        printf("Random generation failed, ret = %d\n", ret);
        wc_FreeRng(&global_rng);
        return 1;
    }

    // Print random bytes
    printf("Generated %d random bytes:\n", 32);
    for (int i = 0; i < 32; i++) {
        printf("%02X", buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
        else
            printf(" ");
    }

    printf("--------------------------ML_KEM_512-------------------------\n");
	MlKemKey* Bench_key = wc_MlKemKey_New(WC_ML_KEM_512, NULL, INVALID_DEVID);
    if (wc_MlKemKey_MakeKey(Bench_key, &global_rng) != 0) printf("Error: MlKem key creation failed.\n");

    #define PUB_SIZE  WC_ML_KEM_512_PUBLIC_KEY_SIZE
    #define PRIV_SIZE WC_ML_KEM_512_PRIVATE_KEY_SIZE
 
    unsigned char pubK[PUB_SIZE];
    unsigned char privK[PRIV_SIZE];

    // Encode public key 
    ret = wc_MlKemKey_EncodePublicKey(Bench_key, pubK, PUB_SIZE);
    if (ret != 0) {
        printf("Public key encode failed: %d\n", ret);
    }

    // Encode private key
    ret = wc_MlKemKey_EncodePrivateKey(Bench_key, privK, PRIV_SIZE);
    if (ret != 0) {
        printf("Private key encode failed: %d\n", ret);
    }

    printf("\nPrivate key\n");
    for (int i = 0; i < PRIV_SIZE; i++) {
        printf("%02x", privK[i]);
    }
    printf("\nPublic key\n");
    for (int i = 0; i < PUB_SIZE; i++) {
        printf("%02x", pubK[i]);
    }
    printf("\n\n");

    wc_MlKemKey_Free(Bench_key);

    printf("=== wolfSSL TLS Test Start ===\n");

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create TLS 1.3 client context */
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        printf("wolfSSL_CTX_new FAILED\n");
        return -1;
    }

    /* Install dummy send/recv callbacks */
    wolfSSL_SetIORecv(ctx, my_IO_Recv);
    wolfSSL_SetIOSend(ctx, my_IO_Send);

    /* Create SSL session */
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) {
        printf("wolfSSL_new FAILED\n");
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    printf("Starting TLS 1.3 handshake...\n");

    ret = wolfSSL_connect(ssl);

    if (ret == WOLFSSL_SUCCESS) {
        printf("Handshake SUCCESS (unexpected on bare metal)\n");
    } else {
        int err = wolfSSL_get_error(ssl, ret);
        printf("wolfSSL_connect returned error %d\n", err);

        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            printf("wolfSSL functional: WANT_READ/WRITE expected.\n");
        } else {
            printf("wolfSSL unexpected error: %d\n", err);
        }
    }

    /* Cleanup */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    printf("=== wolfSSL TLS Test Complete ===\n");

    return 0;
}






//     /* Initialize SDCard */
//     // sdcard_init();
    // spisdcard_init();
//     printf("sdcard_init() done\n");

//     /* Bind FatFS to SPI backend */
    // fatfs_set_ops_spisdcard();
//     printf("fatfs_set_ops_sdcard() done\n");
    
//     /* Mount filesystem */
//     FRESULT fr = f_mount(&fs, "", 1);  //MS-DOS partition table + FAT32 Filesystem
//     printf("f_mount -> %d\n", fr);
//     if (fr != FR_OK) {
//         printf("mount failed\n");
//         return 1;
//     }

//     FIL file;
//     UINT bytes=0;

//     /* PHASE 1 — READ existing file */
//     printf("\n[PHASE 1] Opening test.txt for READ...\n");
//     fr = f_open(&file, "Work.txt", FA_READ | FA_OPEN_EXISTING);
//     printf("[PHASE 1] f_open -> %d\n", fr);
//     if (fr != FR_OK) return 1;

//     static char buf[4096];
//     memset(buf, 0, sizeof(buf));

//     fr = f_read(&file, buf, sizeof(buf)-1, &bytes);
//     printf("[PHASE 1] f_read -> %d, bytes=%u\n", fr, bytes);
//     printf("[PHASE 1] Contents BEFORE write:\n%s\n", buf);

//     f_close(&file);
//     bytes=0;

//     /* PHASE 2 — file write */
//     printf("\n[PHASE 2] Opening test.txt for WRITE + TRUNCATE...\n");
//     fr = f_open(&file, "Work.txt", FA_WRITE | FA_OPEN_EXISTING);
//     printf("[PHASE 2] f_open -> %d\n", fr);
//     if (fr != FR_OK) return 1;

//     f_lseek(&file, f_size(&file));
//     // f_truncate(&file); 

//     const char *msg = "\nHELLO TO THE WORLD\n";
//     fr = f_write(&file, msg, strlen(msg), &bytes); 
//     printf("[PHASE 2] f_write -> %d, bytes=%u\n", fr, bytes);
 
//     f_close(&file);// IT FAILS HERE
//     bytes=0;

//     /* PHASE 3 — Read again */
//     printf("\n[PHASE 3] Opening test.txt for READ again...\n");
//     fr = f_open(&file, "Work.txt", FA_READ | FA_OPEN_EXISTING);
//     printf("[PHASE 3] f_open -> %d\n", fr);
//     if (fr != FR_OK) return 1;

//     memset(buf, 0, sizeof(buf));

//     fr = f_read(&file, buf, sizeof(buf)-1, &bytes);
//     printf("[PHASE 3] f_read -> %d, bytes=%u\n", fr, bytes);
//     printf("[PHASE 3] Contents AFTER write:\n%s\n", buf);

//     f_close(&file);

//     printf("\n=== SD TEST COMPLETE ===\n");