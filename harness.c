#include "civetweb.h"
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static struct mg_context *ctx = NULL; // server context
static unsigned short PORT_NUM_HTTP = 0; // port number we are running the server on
static uint64_t call_count = 0; // how many times we have called the fuzzer 

const char *init_options[] = {
    "listening_ports","0", // automatically pick free tcp port at runtime
    "document_root",".",
    NULL
};

static void civetweb_exit(void) {
    mg_stop(ctx);
    ctx = NULL;
}

// https://github.com/civetweb/civetweb/blob/7f95a2632ef651402c15c39b72c4620382dd82bf/fuzztest/fuzzmain.c#L74
static void civetweb_init(void) {
    struct mg_callbacks callbacks;
    struct mg_server_port ports[8];
    memset(&callbacks, 0, sizeof(callbacks));
    memset(ports, 0, sizeof(ports));

    ctx = mg_start(&callbacks, NULL, init_options);
    if (!ctx) {
        fprintf(stderr, "Failed to start CivetWeb\n");
        exit(1);
    }
    int ret = mg_get_server_ports(ctx, 8, ports);
    if (ret < 1) {
        fprintf(stderr, "Failed to get CivetWeb ports\n");
        exit(1);
    }
    PORT_NUM_HTTP = ports[0].port;
    sleep(5);
    atexit(civetweb_exit);
}

static int send_chunk(const uint8_t *data, size_t size) {
    // make a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Socket initialization failed\n");
        return 1;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(PORT_NUM_HTTP);

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        close(sock);
        return 1;
    }

    send(sock, data, size, 0);
    char buf[1024];

    // recv data but don't do anything
    //  This can result in a deadlock..
    // Ideally, we do want to wait for the program to exit/finish
   // processing our input, otherwise we might not match the coverage to
   // inputs correctly

   //while (recv(sock, buf, sizeof(buf), 0) > 0) {}
    shutdown(sock, SHUT_RDWR); // close read write required ...
    close(sock);
    return 0;
}

struct ThreadArgs {
    const uint8_t *data;
    size_t len;
} typedef ThreadArgs;

static void* fuzz_thread(void *arg) {
    ThreadArgs *t = (ThreadArgs*)arg;
    send_chunk(t->data, t->len);
    return NULL;
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
    if (size < 4) return 0;
    // if calling for the first time, initialize civet web
    if (call_count == 0) civetweb_init();
    call_count = 1;

    // divide data into 4 chunks, each thread gets equal amount of data
    size_t chunkSize = size / 4;
    pthread_t thr[4];
    ThreadArgs ta[4];

    for (int i = 0; i < 4; i++) {
        ta[i].data = (const uint8_t*) data + (i * chunkSize);
        ta[i].len = chunkSize;
        pthread_create(&thr[i], NULL, fuzz_thread, &ta[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(thr[i], NULL);
    }

    return 0;
}

