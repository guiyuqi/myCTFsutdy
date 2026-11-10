/* easytl: TLS1.3 external-PSK client using OpenSSL's psk_use_session_callback.
 *
 * The server (firmware binary) accepts ONLY:
 *   identity  = "1401518dc5d7641ccd41593a5d812410"   (32 chars, hard check)
 *   PSK       = HMAC-SHA512(key = hex2buf(96 hex chars at 0x825060 48B),
 *                           msg = identity)  -> 64 bytes
 *   session cipher = TLS_AES_256_GCM_SHA384  (=> binder hash SHA-384, 48 B)
 * All the TLS plumbing (key_share, binder, key schedule, record crypto) is
 * delegated to OpenSSL.
 *
 * usage:
 *   ./psk_client <host> <port> [mode]
 *     mode 0 (default) : handshake, then run the known app protocol (add+get)
 *     mode 1           : handshake with a long SNI, then send a TLS alert
 *                        (exercises the hidden 0x40304d memcpy path)
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* No OpenSSL headers on this box: declare the few symbols we need.
 * All of them are exported by libssl.so.3 / libcrypto.so.3 (3.5.5). */
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_session_st SSL_SESSION;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_method_st SSL_METHOD;
typedef struct evp_md_st EVP_MD;

extern const SSL_METHOD *TLS_client_method(void);
extern SSL_CTX *SSL_CTX_new(const SSL_METHOD *);
extern void SSL_CTX_free(SSL_CTX *);
extern long SSL_CTX_ctrl(SSL_CTX *, int, long, void *);
extern long SSL_ctrl(SSL *, int, long, void *);
extern const SSL_CIPHER *SSL_get_current_cipher(const SSL *);
extern const char *SSL_CIPHER_get_name(const SSL_CIPHER *);
#define SSL_CTRL_SET_MIN_PROTO_VERSION 123
#define SSL_CTRL_SET_MAX_PROTO_VERSION 124
#define SSL_CTRL_SET_TLSEXT_HOSTNAME    55
#define TLSEXT_NAMETYPE_host_name        0
#define SSL_CTX_set_min_proto_version(c, v) SSL_CTX_ctrl((c), SSL_CTRL_SET_MIN_PROTO_VERSION, (v), 0)
#define SSL_CTX_set_max_proto_version(c, v) SSL_CTX_ctrl((c), SSL_CTRL_SET_MAX_PROTO_VERSION, (v), 0)
#define SSL_set_tlsext_host_name(s, n) SSL_ctrl((s), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void *)(n))
#define SSL_get_cipher_name(s) SSL_CIPHER_get_name(SSL_get_current_cipher(s))
extern int SSL_CTX_set_ciphersuites(SSL_CTX *, const char *);
extern int SSL_CTX_set_psk_use_session_callback(SSL_CTX *,
    int (*cb)(SSL *, const EVP_MD *, const unsigned char **, size_t *, SSL_SESSION **));
extern SSL *SSL_new(SSL_CTX *);
extern void SSL_free(SSL *);
extern int SSL_set_fd(SSL *, int);
extern int SSL_get_fd(const SSL *);
extern int SSL_connect(SSL *);
extern int SSL_read(SSL *, void *, int);
extern int SSL_write(SSL *, const void *, int);
extern int SSL_shutdown(SSL *);
extern const char *SSL_get_version(const SSL *);
extern SSL_SESSION *SSL_SESSION_new(void);
extern int SSL_SESSION_set1_master_key(SSL_SESSION *, const unsigned char *, size_t);
extern int SSL_SESSION_set_cipher(SSL_SESSION *, const SSL_CIPHER *);
extern int SSL_SESSION_set_protocol_version(SSL_SESSION *, int);
extern const SSL_CIPHER *SSL_CIPHER_find(SSL *, const unsigned char *);

#define TLS1_3_VERSION 0x0304

static const char *ID_STR = "1401518dc5d7641ccd41593a5d812410";
static const unsigned char PSK[64] = {
    0x8b, 0xd3, 0xd0, 0x2f, 0x8a, 0xc2, 0xe2, 0xa0, 0x63, 0x73, 0x57, 0x79,
    0xb0, 0xa2, 0xea, 0x98, 0x0d, 0x0b, 0xaa, 0x08, 0x31, 0xed, 0x9f, 0xce,
    0x8b, 0x81, 0x25, 0xd7, 0x9a, 0xf5, 0x98, 0xb5, 0x13, 0x82, 0xd3, 0x23,
    0x1b, 0x15, 0x63, 0x4d, 0xc4, 0xe5, 0xc5, 0x1a, 0xa1, 0xe5, 0x7a, 0xfc,
    0x03, 0x8b, 0xbd, 0xf1, 0x12, 0x17, 0xb4, 0x02, 0x88, 0x7a, 0xd7, 0x44,
    0xf7, 0x37, 0xe9, 0x52
};

static int use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
                          size_t *idlen, SSL_SESSION **sess)
{
    static const unsigned char cipher_bytes[2] = {0x13, 0x02}; /* AES_256_GCM_SHA384 */
    SSL_SESSION *s = SSL_SESSION_new();
    const SSL_CIPHER *c;
    (void)md;
    if (s == NULL)
        return 0;
    if (!SSL_SESSION_set1_master_key(s, PSK, sizeof(PSK)))
        return 0;
    c = SSL_CIPHER_find(ssl, cipher_bytes);
    if (c == NULL || !SSL_SESSION_set_cipher(s, c))
        return 0;
    if (!SSL_SESSION_set_protocol_version(s, TLS1_3_VERSION))
        return 0;
    *id = (const unsigned char *)ID_STR;
    *idlen = strlen(ID_STR);
    *sess = s;
    return 1;
}

static int tcp_connect(const char *host, int port)
{
    struct sockaddr_in sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (fd < 0)
        return -1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
        return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;
    return fd;
}

static int read_some(SSL *ssl, unsigned char *buf, int cap, int timeout_ms)
{
    int n;
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(SSL_get_fd(ssl), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    n = SSL_read(ssl, buf, cap);
    return n;
}

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 1443;
    int mode = argc > 3 ? atoi(argv[3]) : 0;
    SSL_CTX *ctx;
    SSL *ssl;
    int fd, ret;
    unsigned char buf[4096];
    char sni[256];

    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");
    if (!SSL_CTX_set_psk_use_session_callback(ctx, use_session_cb)) {
        fprintf(stderr, "set_psk_use_session_callback failed\n");
        return 1;
    }

    fd = tcp_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if (mode == 1) {
        memset(sni, 'A', sizeof(sni) - 1);
        sni[sizeof(sni) - 1] = 0;
        SSL_set_tlsext_host_name(ssl, sni);   /* long SNI -> G970f58 = 255 */
    } else {
        SSL_set_tlsext_host_name(ssl, "easytl");
    }

    ret = SSL_connect(ssl);
    if (ret != 1) {
        printf("SSL_connect failed: %d\n", ret);
        return 1;
    }
    printf("HANDSHAKE OK: version=%s cipher=%s\n",
           SSL_get_version(ssl), SSL_get_cipher_name(ssl));

    if (mode == 1) {
        /* trigger the info-callback path: send a warning close_notify alert */
        static const unsigned char close_notify[7] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};
        printf("sending raw close_notify alert record\n");
        send(fd, close_notify, sizeof(close_notify), 0);
        ret = read_some(ssl, buf, sizeof(buf), 2000);
        printf("after alert: SSL_read=%d\n", ret);
        close(fd);
        return 0;
    }

    /* ---- application protocol: add + get (same bytes as the python harness) */
    {
        unsigned char pkt[256];
        int off = 0;
        const char *name = "AAAAAAAAAAAAAAAA";  /* 16 */
        const char *key = "BBBBBBBBBBBBBBBB";   /* 16 */
        const char *data = "hello-world-1234";  /* 16 */
        unsigned int dlen = 16;
        static const unsigned char digest[16] = {
            0xad, 0xfb, 0x27, 0x17, 0xd9, 0x09, 0xdb, 0xfa,
            0xad, 0x4f, 0x93, 0xab, 0xc1, 0x4f, 0x14, 0xdc
        };
        /* add: op 0x38432a87 */
        pkt[off++] = 0x87; pkt[off++] = 0x2a; pkt[off++] = 0x43; pkt[off++] = 0x38;
        memcpy(pkt + off, name, 16); off += 16;
        memcpy(pkt + off, key, 16); off += 16;
        pkt[off++] = (unsigned char)(dlen & 0xff);
        pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
        memcpy(pkt + off, data, dlen); off += dlen;
        SSL_write(ssl, pkt, off);
        printf("sent add (%d bytes)\n", off);

        /* get: op 0x89954d3e + digest */
        pkt[0] = 0x3e; pkt[1] = 0x4d; pkt[2] = 0x95; pkt[3] = 0x89;
        memcpy(pkt + 4, digest, 16);
        SSL_write(ssl, pkt, 20);
        printf("sent get (%d bytes)\n", 20);
        ret = read_some(ssl, buf, sizeof(buf), 2000);
        printf("get -> n=%d hex=", ret);
        for (int i = 0; i < ret && i < 32; i++)
            printf("%02x", buf[i]);
        printf("  ascii=\"");
        for (int i = 0; i < ret && i < 32; i++)
            putchar((buf[i] >= 32 && buf[i] < 127) ? buf[i] : '.');
        printf("\"\n");

        /* liveness: unknown opcode -> expect "error" */
        pkt[0] = 0xde; pkt[1] = 0xad; pkt[2] = 0xbe; pkt[3] = 0xef;
        SSL_write(ssl, pkt, 4);
        ret = read_some(ssl, buf, sizeof(buf), 2000);
        printf("unknown-op -> n=%d \"%.*s\"\n", ret, ret > 0 ? ret : 0, buf);
    }

    SSL_shutdown(ssl);
    close(fd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
