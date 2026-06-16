/*
 * RemotePipeList - list remote named pipes via SMB2 on IPC$
 * Self-contained SMB2 2.0.2 client with Windows SSPI (current credentials).
 */

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sspi.h>
#include <bcrypt.h>

#include "../beacon.h"
#include "print.h"

#ifdef BOF
#define malloc(sz) HeapAlloc(GetProcessHeap(), 0, (sz))
#define calloc(n, sz) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n) * (sz))
#define free(p) HeapFree(GetProcessHeap(), 0, (p))
#endif

#define SMB2_HEADER_SIZE           64
#define SMB2_SPL_SIZE              4
#define SMB2_GUID_SIZE             16
#define SMB2_FD_SIZE               16
#define SMB2_SIGNATURE_SIZE        16
#define SMB2_KEY_SIZE              16

#define SMB2_MAGIC                 0x424D53FEu /* LE: FE 'S' 'M' 'B' */

#define SMB2_NEGOTIATE             0
#define SMB2_SESSION_SETUP         1
#define SMB2_LOGOFF                2
#define SMB2_TREE_CONNECT          3
#define SMB2_TREE_DISCONNECT       4
#define SMB2_CREATE                5
#define SMB2_CLOSE                 6
#define SMB2_QUERY_DIRECTORY       14

#define SMB2_STATUS_SUCCESS                    0x00000000u
#define SMB2_STATUS_MORE_PROCESSING_REQUIRED   0xC0000016u
#define SMB2_STATUS_NO_MORE_FILES              0x80000006u

#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002
#define SMB2_FLAGS_SERVER_TO_REDIR      0x00000001u
#define SMB2_FLAGS_SIGNED               0x00000008u

#define SMB2_VERSION_0202               0x0202
#define SMB2_VERSION_0210               0x0210
#define SMB2_GLOBAL_CAP_DFS             0x00000001u
#define SMB2_FILE_DIRECTORY_INFORMATION 0x01
#define SMB2_RESTART_SCANS              0x01

#define SMB2_FILE_DIRECTORY_FILE        0x00000001u
#define SMB2_FILE_OPEN                  0x00000001u
#define SMB2_FILE_ATTRIBUTE_DIRECTORY   0x00000010u
#define SMB2_FILE_LIST_DIRECTORY        0x00000001u
#define SMB2_FILE_READ_ATTRIBUTES       0x00000080u
#define SMB2_FILE_SHARE_READ            0x00000001u
#define SMB2_FILE_SHARE_WRITE           0x00000002u
#define SMB2_IMPERSONATION_IMPERSONATION 0x00000002u
#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB 0x0001

#define SMB2_NEGOTIATE_REQUEST_SIZE        36
#define SMB2_SESSION_SETUP_REQUEST_SIZE    25
#define SMB2_TREE_CONNECT_REQUEST_SIZE     9
#define SMB2_CREATE_REQUEST_SIZE           57
#define SMB2_QUERY_DIRECTORY_REQUEST_SIZE  33
#define SMB2_CLOSE_REQUEST_SIZE            24
#define SMB2_TREE_DISCONNECT_REQUEST_SIZE  4
#define SMB2_LOGOFF_REQUEST_SIZE           4

typedef struct {
    SOCKET sock;
    uint64_t message_id;
    uint64_t session_id;
    uint32_t tree_id;
    uint16_t dialect;
    uint8_t client_security_mode;
    int sign;
    uint8_t signing_key[SMB2_KEY_SIZE];
    size_t signing_key_len;
    char server[260];
    char last_error[512];
    uint8_t *neg_token;
    size_t neg_token_len;
} smb_ctx;

typedef struct {
    CredHandle cred;
    CtxtHandle ctx;
    int cred_ok;
    int ctx_ok;
    wchar_t target[280];
} sspi_ctx;

static void set_error(smb_ctx *ctx, const char *fmt, ...)
{
    va_list ap;
    if (!ctx)
        return;
    va_start(ap, fmt);
    vsnprintf(ctx->last_error, sizeof(ctx->last_error), fmt, ap);
    va_end(ap);
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t lo = rd32(p);
    uint64_t hi = rd32(p + 4);
    return lo | (hi << 32);
}

static void wr8(uint8_t *p, uint8_t v)
{
    *p = v;
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void wr64(uint8_t *p, uint64_t v)
{
    wr32(p, (uint32_t)(v & 0xffffffffu));
    wr32(p + 4, (uint32_t)(v >> 32));
}

static size_t pad64(size_t n)
{
    return (n + 7) & ~(size_t)7;
}

static size_t pad32(size_t n)
{
    return (n + 3) & ~(size_t)3;
}

/* SMB2 structure sizes include a 2-byte StructureSize field; wire fixed part is even-rounded. */
static size_t smb2_fixed_size(uint16_t structure_size)
{
    return (size_t)(structure_size & 0xfffeu);
}

/* SMB direct TCP: 0x00 + 3-byte big-endian length */
static void wr_nb_len(uint8_t *p, uint32_t len)
{
    p[0] = 0;
    p[1] = (uint8_t)((len >> 16) & 0xff);
    p[2] = (uint8_t)((len >> 8) & 0xff);
    p[3] = (uint8_t)(len & 0xff);
}

static uint32_t rd_nb_len(const uint8_t *p)
{
    return ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int utf8_to_utf16(const char *in, uint16_t **out, size_t *out_chars)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    uint16_t *w;
    if (n <= 0)
        return -1;
    w = (uint16_t *)malloc((size_t)n * sizeof(uint16_t));
    if (!w)
        return -1;
    if (MultiByteToWideChar(CP_UTF8, 0, in, -1, (LPWSTR)w, n) == 0) {
        free(w);
        return -1;
    }
    *out = w;
    *out_chars = (size_t)(n - 1);
    return 0;
}

static char *utf16_to_utf8(const uint16_t *in, size_t chars)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)in, (int)chars, NULL, 0, NULL, NULL);
    char *s;
    if (n <= 0)
        return NULL;
    s = (char *)malloc((size_t)n + 1);
    if (!s)
        return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)in, (int)chars, s, n, NULL, NULL) == 0) {
        free(s);
        return NULL;
    }
    s[n] = '\0';
    return s;
}

static int smb_sign(smb_ctx *ctx, uint8_t *pkt, size_t len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;
    uint8_t digest[32];
    DWORD dig_len = 0;

    if (!ctx->sign || ctx->signing_key_len == 0)
        return 0;

    memset(pkt + 48, 0, SMB2_SIGNATURE_SIZE);
    wr32(pkt + 16, rd32(pkt + 16) | SMB2_FLAGS_SIGNED);

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0)
        return -1;
    st = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&dig_len, sizeof(dig_len), &dig_len, 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }
    st = BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)ctx->signing_key, (ULONG)ctx->signing_key_len, 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }
    st = BCryptHashData(hash, pkt, (ULONG)len, 0);
    if (st != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }
    st = BCryptFinishHash(hash, digest, dig_len, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0)
        return -1;

    memcpy(pkt + 48, digest, SMB2_SIGNATURE_SIZE);
    return 0;
}

static void smb_build_header(smb_ctx *ctx, uint8_t *hdr, uint16_t cmd, uint32_t tree_id, int sign_pkt)
{
    memset(hdr, 0, SMB2_HEADER_SIZE);
    hdr[0] = 0xFE;
    hdr[1] = 'S';
    hdr[2] = 'M';
    hdr[3] = 'B';
    wr16(hdr + 4, SMB2_HEADER_SIZE);
    wr16(hdr + 12, cmd);
    wr16(hdr + 14, 64);
    wr32(hdr + 20, 0);
    wr64(hdr + 24, ctx->message_id++);
    wr32(hdr + 32, 0xFEFF);
    wr32(hdr + 36, tree_id);
    wr64(hdr + 40, ctx->session_id);
    (void)sign_pkt;
}

static int smb_send_recv(smb_ctx *ctx, uint8_t *pkt, size_t pkt_len, uint8_t **resp, size_t *resp_len)
{
    uint32_t spl = (uint32_t)pkt_len;
    uint8_t lenbuf[4];
    uint32_t rlen;
    uint8_t *buf;
    size_t got;
    int n;

    if (ctx->sign && smb_sign(ctx, pkt, pkt_len) != 0) {
        set_error(ctx, "signing failed");
        return -1;
    }

    wr_nb_len(lenbuf, spl);

    if (send(ctx->sock, (const char *)lenbuf, 4, 0) != 4 ||
        send(ctx->sock, (const char *)pkt, (int)pkt_len, 0) != (int)pkt_len) {
        set_error(ctx, "send failed (%d)", WSAGetLastError());
        return -1;
    }

    got = 0;
    while (got < 4) {
        n = recv(ctx->sock, (char *)lenbuf + got, (int)(4 - got), 0);
        if (n <= 0) {
            set_error(ctx, "recv length failed (%d)", WSAGetLastError());
            return -1;
        }
        got += (size_t)n;
    }
    if (lenbuf[0] != 0) {
        set_error(ctx, "invalid netbios length prefix");
        return -1;
    }
    rlen = rd_nb_len(lenbuf);
    if (rlen < SMB2_HEADER_SIZE || rlen > 16 * 1024 * 1024) {
        set_error(ctx, "invalid response length %u", rlen);
        return -1;
    }

    buf = (uint8_t *)malloc(rlen);
    if (!buf)
        return -1;
    got = 0;
    while (got < rlen) {
        n = recv(ctx->sock, (char *)buf + got, (int)(rlen - got), 0);
        if (n <= 0) {
            free(buf);
            set_error(ctx, "recv body failed (%d)", WSAGetLastError());
            return -1;
        }
        got += (size_t)n;
    }

    *resp = buf;
    *resp_len = rlen;
    return 0;
}

static int smb_exchange(smb_ctx *ctx, uint16_t cmd, uint32_t tree_id,
                          const uint8_t *body, size_t body_len,
                          uint8_t **resp, size_t *resp_len)
{
    uint8_t *pkt;
    size_t pkt_len = SMB2_HEADER_SIZE + body_len;
    int rc;

    pkt = (uint8_t *)malloc(pkt_len);
    if (!pkt)
        return -1;
    smb_build_header(ctx, pkt, cmd, tree_id, ctx->sign && ctx->session_id != 0);
    memcpy(pkt + SMB2_HEADER_SIZE, body, body_len);
    rc = smb_send_recv(ctx, pkt, pkt_len, resp, resp_len);
    free(pkt);
    return rc;
}

static uint32_t smb_resp_status(const uint8_t *resp)
{
    return rd32(resp + 8);
}

static int host_is_numeric(const char *host)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    rc = (getaddrinfo(host, NULL, &hints, &res) == 0);
    if (res)
        freeaddrinfo(res);
    return rc;
}

static int addr_to_ip_string(const struct addrinfo *ai, char *buf, size_t buflen)
{
    if (ai->ai_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
        return inet_ntop(AF_INET, &sin->sin_addr, buf, buflen) != NULL;
    }
    if (ai->ai_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
        return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, buflen) != NULL;
    }
    return 0;
}

/*
 * Hostname targets use Kerberos against cifs/<name>, which often fails tree
 * connect (0xc0000022) even when DNS/TCP work. Use the connected peer IP for
 * SSPI and UNC so auth matches the direct-IP code path (NTLM).
 */
static void use_connected_ip_for_smb(smb_ctx *ctx, const char *host, const struct addrinfo *ai)
{
    char ip[INET6_ADDRSTRLEN];

    if (host_is_numeric(host) || !ai)
        return;
    if (addr_to_ip_string(ai, ip, sizeof(ip))) {
        strncpy(ctx->server, ip, sizeof(ctx->server) - 1);
        ctx->server[sizeof(ctx->server) - 1] = '\0';
    }
}

static int tcp_connect(smb_ctx *ctx, const char *host)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    struct addrinfo *connected_ai = NULL;
    char port[] = "445";
    SOCKET s = INVALID_SOCKET;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
        set_error(ctx, "getaddrinfo failed (%d)", err);
        return -1;
    }

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            connected_ai = ai;
            break;
        }
        closesocket(s);
        s = INVALID_SOCKET;
    }

    if (s != INVALID_SOCKET && connected_ai)
        use_connected_ip_for_smb(ctx, host, connected_ai);

    freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
        set_error(ctx, "connect failed (%d)", WSAGetLastError());
        return -1;
    }

    ctx->sock = s;
    return 0;
}

/* --- SSPI --- */

static sspi_ctx *sspi_init(const char *server)
{
    sspi_ctx *a;
    TimeStamp exp;
    SECURITY_STATUS st;
    const wchar_t prefix[] = L"cifs/";
    size_t prefix_len = (sizeof(prefix) / sizeof(prefix[0])) - 1;
    int slen;

    a = (sspi_ctx *)calloc(1, sizeof(*a));
    if (!a)
        return NULL;

    slen = MultiByteToWideChar(CP_UTF8, 0, server, -1, NULL, 0);
    if (slen <= 0 || prefix_len + (size_t)slen >= 280) {
        free(a);
        return NULL;
    }
    memcpy(a->target, prefix, prefix_len * sizeof(wchar_t));
    if (MultiByteToWideChar(CP_UTF8, 0, server, -1, a->target + prefix_len, 280 - (int)prefix_len) == 0) {
        free(a);
        return NULL;
    }

    st = AcquireCredentialsHandleW(NULL, (LPWSTR)L"Negotiate", SECPKG_CRED_OUTBOUND,
                                   NULL, NULL, NULL, NULL, &a->cred, &exp);
    if (st != SEC_E_OK) {
        free(a);
        return NULL;
    }
    a->cred_ok = 1;
    return a;
}

static void sspi_free(sspi_ctx *a)
{
    if (!a)
        return;
    if (a->ctx_ok)
        DeleteSecurityContext(&a->ctx);
    if (a->cred_ok)
        FreeCredentialsHandle(&a->cred);
    free(a);
}

static int sspi_blob(sspi_ctx *a, const uint8_t *in, size_t in_len,
                     uint8_t **out, uint16_t *out_len)
{
    SecBuffer tok;
    SecBufferDesc out_desc;
    SecBufferDesc in_desc;
    SecBuffer in_tok;
    ULONG attrs;
    TimeStamp exp;
    SECURITY_STATUS st;

    *out = NULL;
    *out_len = 0;

    memset(&tok, 0, sizeof(tok));
    tok.BufferType = SECBUFFER_TOKEN;
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &tok;

    if (in && in_len > 0) {
        in_tok.BufferType = SECBUFFER_TOKEN;
        in_tok.pvBuffer = (void *)in;
        in_tok.cbBuffer = (ULONG)in_len;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 1;
        in_desc.pBuffers = &in_tok;
    }

    st = InitializeSecurityContextW(
        &a->cred, a->ctx_ok ? &a->ctx : NULL, a->target,
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_USE_SUPPLIED_CREDS,
        0, 0, (in && in_len) ? &in_desc : NULL, 0,
        a->ctx_ok ? NULL : &a->ctx, &out_desc, &attrs, &exp);

    if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) {
        if (tok.pvBuffer)
            FreeContextBuffer(tok.pvBuffer);
        return (int)st;
    }
    a->ctx_ok = 1;

    if (tok.cbBuffer == 0 || !tok.pvBuffer)
        return 0;

    *out = (uint8_t *)malloc(tok.cbBuffer);
    if (!*out) {
        FreeContextBuffer(tok.pvBuffer);
        return -1;
    }
    memcpy(*out, tok.pvBuffer, tok.cbBuffer);
    if (tok.cbBuffer > 0xFFFF) {
        free(*out);
        FreeContextBuffer(tok.pvBuffer);
        return -1;
    }
    *out_len = (uint16_t)tok.cbBuffer;
    FreeContextBuffer(tok.pvBuffer);
    return 0;
}

static int sspi_session_key(sspi_ctx *a, uint8_t *key, size_t *key_len)
{
    SecPkgContext_SessionKey sk;
    SECURITY_STATUS st;

    if (!a->ctx_ok)
        return -1;
    memset(&sk, 0, sizeof(sk));
    st = QueryContextAttributesW(&a->ctx, SECPKG_ATTR_SESSION_KEY, &sk);
    if (st != SEC_E_OK || !sk.SessionKey || sk.SessionKeyLength == 0)
        return -1;
    if (sk.SessionKeyLength > SMB2_KEY_SIZE)
        return -1;
    memcpy(key, sk.SessionKey, sk.SessionKeyLength);
    *key_len = sk.SessionKeyLength;
    return 0;
}

/* --- SMB2 commands --- */

static int smb2_negotiate(smb_ctx *ctx)
{
    uint8_t body[64];
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    uint16_t dialect;
    uint8_t guid[SMB2_GUID_SIZE];
    size_t i;

    memset(body, 0, sizeof(body));
    wr16(body + 0, SMB2_NEGOTIATE_REQUEST_SIZE);
    wr16(body + 2, 2);
    ctx->client_security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
    wr16(body + 4, ctx->client_security_mode);
    wr32(body + 8, SMB2_GLOBAL_CAP_DFS);
    for (i = 0; i < SMB2_GUID_SIZE; i++)
        guid[i] = (uint8_t)((GetTickCount() + (DWORD)i) & 0xff);
    memcpy(body + 12, guid, SMB2_GUID_SIZE);
    wr16(body + 36, SMB2_VERSION_0202);
    wr16(body + 38, SMB2_VERSION_0210);

    if (smb_exchange(ctx, SMB2_NEGOTIATE, 0, body, 40, &resp, &resp_len) != 0)
        return -1;

    if (smb_resp_status(resp) != SMB2_STATUS_SUCCESS) {
        set_error(ctx, "negotiate status 0x%08x", smb_resp_status(resp));
        free(resp);
        return -1;
    }

    {
        uint16_t sec_mode = rd16(resp + SMB2_HEADER_SIZE + 2);
        dialect = rd16(resp + SMB2_HEADER_SIZE + 4);
        ctx->dialect = dialect;
        if (dialect != SMB2_VERSION_0202 && dialect != SMB2_VERSION_0210) {
            set_error(ctx, "unsupported dialect 0x%04x (need 0x0202/0x0210)", dialect);
            free(resp);
            return -1;
        }
        ctx->sign = 0;
        if (sec_mode & (SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED))
            ctx->sign = 1;

        {
            uint16_t off = rd16(resp + SMB2_HEADER_SIZE + 56);
            uint16_t len = rd16(resp + SMB2_HEADER_SIZE + 58);
            if (len > 0 && (size_t)off + len <= resp_len) {
                ctx->neg_token = (uint8_t *)malloc(len);
                if (!ctx->neg_token) {
                    free(resp);
                    return -1;
                }
                memcpy(ctx->neg_token, resp + off, len);
                ctx->neg_token_len = len;
            }
        }
    }

    free(resp);
    return 0;
}

static int smb2_session_setup(smb_ctx *ctx, sspi_ctx *sspi)
{
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    uint8_t *token = NULL;
    uint16_t token_len = 0;
    uint8_t *spnego_in = NULL;
    size_t spnego_in_len = 0;
    uint32_t status = 0;
    int round;

    /* Match libsmb2/win_sspi: first InitializeSecurityContext has no negotiate input. */
    free(ctx->neg_token);
    ctx->neg_token = NULL;
    ctx->neg_token_len = 0;

    for (round = 0; round < 8; round++) {
        uint8_t *body = NULL;
        size_t body_len;
        uint16_t sec_off = SMB2_HEADER_SIZE + 24;

        {
            int sspi_st = sspi_blob(sspi, spnego_in, spnego_in_len, &token, &token_len);
            if (sspi_st != 0) {
                set_error(ctx, "SSPI failed (0x%08x)", (unsigned)sspi_st);
                free(spnego_in);
                return -1;
            }
        }
        if (token_len == 0) {
            set_error(ctx, "SSPI produced empty token");
            free(spnego_in);
            return -1;
        }
        free(spnego_in);
        spnego_in = NULL;
        spnego_in_len = 0;

        body_len = 24 + (size_t)token_len;
        body = (uint8_t *)calloc(1, body_len);
        if (!body) {
            free(token);
            free(spnego_in);
            return -1;
        }

        wr16(body + 0, SMB2_SESSION_SETUP_REQUEST_SIZE);
        wr8(body + 2, 0);
        wr8(body + 3, ctx->client_security_mode);
        wr32(body + 4, 0);
        wr32(body + 8, 0);
        wr16(body + 12, sec_off);
        wr16(body + 14, token_len);
        wr64(body + 16, 0);
        if (token_len > 0)
            memcpy(body + 24, token, token_len);
        free(token);

        if (smb_exchange(ctx, SMB2_SESSION_SETUP, 0, body, body_len, &resp, &resp_len) != 0) {
            free(body);
            free(spnego_in);
            return -1;
        }
        free(body);

        status = smb_resp_status(resp);
        ctx->session_id = rd64(resp + 40);

        if (status == SMB2_STATUS_SUCCESS)
            break;

        if (status != SMB2_STATUS_MORE_PROCESSING_REQUIRED) {
            set_error(ctx, "session setup status 0x%08x", status);
            free(resp);
            free(spnego_in);
            return -1;
        }

        {
            uint16_t off = rd16(resp + SMB2_HEADER_SIZE + 4);
            uint16_t len = rd16(resp + SMB2_HEADER_SIZE + 6);
            if (len > 0 && (size_t)off + len <= resp_len) {
                spnego_in = (uint8_t *)malloc(len);
                if (!spnego_in) {
                    free(resp);
                    return -1;
                }
                memcpy(spnego_in, resp + off, len);
                spnego_in_len = len;
            }
        }
        free(resp);
        resp = NULL;
    }

    free(resp);
    free(spnego_in);
    free(ctx->neg_token);
    ctx->neg_token = NULL;

    if (status != SMB2_STATUS_SUCCESS) {
        set_error(ctx, "session setup did not complete (0x%08x)", status);
        return -1;
    }

    if (ctx->sign) {
        if (sspi_session_key(sspi, ctx->signing_key, &ctx->signing_key_len) != 0)
            set_error(ctx, "no session key for signing");
    }

    return 0;
}

static int smb2_tree_connect(smb_ctx *ctx)
{
    uint8_t body[256];
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    char unc[512];
    uint16_t *w = NULL;
    size_t wlen = 0;
    size_t byte_len;
    size_t fix = smb2_fixed_size(SMB2_TREE_CONNECT_REQUEST_SIZE);
    uint16_t path_off = (uint16_t)(SMB2_HEADER_SIZE + fix);

    snprintf(unc, sizeof(unc), "\\\\%s\\IPC$", ctx->server);
    if (utf8_to_utf16(unc, &w, &wlen) != 0)
        return -1;
    byte_len = wlen * 2;

    memset(body, 0, sizeof(body));
    wr16(body + 0, SMB2_TREE_CONNECT_REQUEST_SIZE);
    wr16(body + 2, 0);
    wr16(body + 4, path_off);
    wr16(body + 6, (uint16_t)byte_len);
    memcpy(body + fix, w, byte_len);
    free(w);

    if (smb_exchange(ctx, SMB2_TREE_CONNECT, 0, body, pad64(fix + byte_len),
                     &resp, &resp_len) != 0)
        return -1;

    if (smb_resp_status(resp) != SMB2_STATUS_SUCCESS) {
        set_error(ctx, "tree connect status 0x%08x", smb_resp_status(resp));
        free(resp);
        return -1;
    }

    ctx->tree_id = rd32(resp + 36);
    free(resp);
    return 0;
}

static int smb2_create_root(smb_ctx *ctx, uint8_t file_id[SMB2_FD_SIZE])
{
    uint8_t body[128];
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    size_t fix = smb2_fixed_size(SMB2_CREATE_REQUEST_SIZE);
    size_t body_len = fix + 8; /* empty name: 8-byte pad per [MS-SMB2] */

    memset(body, 0, sizeof(body));
    wr16(body + 0, SMB2_CREATE_REQUEST_SIZE);
    wr8(body + 3, 0);
    wr32(body + 4, SMB2_IMPERSONATION_IMPERSONATION);
    wr32(body + 24, SMB2_FILE_LIST_DIRECTORY | SMB2_FILE_READ_ATTRIBUTES);
    wr32(body + 28, SMB2_FILE_ATTRIBUTE_DIRECTORY);
    wr32(body + 32, SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE);
    wr32(body + 36, SMB2_FILE_OPEN);
    wr32(body + 40, SMB2_FILE_DIRECTORY_FILE);
    wr16(body + 44, (uint16_t)pad32(SMB2_HEADER_SIZE + fix));
    wr16(body + 46, 0);

    if (smb_exchange(ctx, SMB2_CREATE, ctx->tree_id, body, body_len, &resp, &resp_len) != 0)
        return -1;

    if (smb_resp_status(resp) != SMB2_STATUS_SUCCESS) {
        set_error(ctx, "create status 0x%08x", smb_resp_status(resp));
        free(resp);
        return -1;
    }

    memcpy(file_id, resp + SMB2_HEADER_SIZE + 64, SMB2_FD_SIZE);
    free(resp);
    return 0;
}

static int parse_dir_entries(const uint8_t *buf, size_t len)
{
    size_t off = 0;
    int count = 0;

    while (off + 64 <= len) {
        uint32_t next = rd32(buf + off);
        uint32_t name_len = rd32(buf + off + 60);
        char *name;

        if (name_len == 0 || off + 64 + name_len > len)
            break;

        name = utf16_to_utf8((const uint16_t *)(buf + off + 64), name_len / 2);
        if (name && name[0] != '\0' && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            internal_printf("    %s\n", name);
            count++;
        }
        free(name);

        if (next == 0)
            break;
        off += next;
    }
    return count;
}

static int smb2_query_pipes(smb_ctx *ctx, const uint8_t file_id[SMB2_FD_SIZE])
{
    uint8_t body[128];
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    uint16_t *pat = NULL;
    size_t pat_len = 0;
    int total = 0;
    int first = 1;

    if (utf8_to_utf16("*", &pat, &pat_len) != 0)
        return -1;

    for (;;) {
        uint32_t status;
        uint16_t out_off;
        uint32_t out_len;
        const uint8_t *data;
        size_t data_len;

        memset(body, 0, sizeof(body));
        wr16(body + 0, SMB2_QUERY_DIRECTORY_REQUEST_SIZE);
        wr8(body + 2, SMB2_FILE_DIRECTORY_INFORMATION);
        wr8(body + 3, first ? SMB2_RESTART_SCANS : 0);
        wr32(body + 4, 0);
        memcpy(body + 8, file_id, SMB2_FD_SIZE);
        {
            size_t qfix = smb2_fixed_size(SMB2_QUERY_DIRECTORY_REQUEST_SIZE);
            wr16(body + 24, (uint16_t)(SMB2_HEADER_SIZE + qfix));
            wr16(body + 26, (uint16_t)(pat_len * 2));
            wr32(body + 28, 0x10000);
            memcpy(body + qfix, pat, pat_len * 2);

            if (smb_exchange(ctx, SMB2_QUERY_DIRECTORY, ctx->tree_id, body,
                             pad64(qfix + pat_len * 2), &resp, &resp_len) != 0) {
                free(pat);
                return -1;
            }
        }

        status = smb_resp_status(resp);
        if (status == SMB2_STATUS_NO_MORE_FILES) {
            free(resp);
            break;
        }
        if (status != SMB2_STATUS_SUCCESS) {
            set_error(ctx, "query directory status 0x%08x", status);
            free(resp);
            free(pat);
            return -1;
        }

        out_off = rd16(resp + SMB2_HEADER_SIZE + 2);
        out_len = rd32(resp + SMB2_HEADER_SIZE + 4);
        if ((size_t)out_off + out_len > resp_len) {
            set_error(ctx, "malformed query response");
            free(resp);
            free(pat);
            return -1;
        }
        data = resp + out_off;
        data_len = out_len;
        total += parse_dir_entries(data, data_len);
        free(resp);
        first = 0;
    }

    free(pat);
    if (total == 0)
        internal_printf("    (no pipes found)\n");
    return 0;
}

static int smb2_close(smb_ctx *ctx, const uint8_t file_id[SMB2_FD_SIZE])
{
    uint8_t body[64];
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    memset(body, 0, sizeof(body));
    wr16(body + 0, SMB2_CLOSE_REQUEST_SIZE);
    wr16(body + 2, SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB);
    memcpy(body + 8, file_id, SMB2_FD_SIZE);

    if (smb_exchange(ctx, SMB2_CLOSE, ctx->tree_id, body, SMB2_CLOSE_REQUEST_SIZE, &resp, &resp_len) != 0)
        return -1;
    free(resp);
    return 0;
}

static void smb2_disconnect(smb_ctx *ctx)
{
    uint8_t body[8];
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    if (ctx->tree_id) {
        memset(body, 0, sizeof(body));
        wr16(body + 0, SMB2_TREE_DISCONNECT_REQUEST_SIZE);
        smb_exchange(ctx, SMB2_TREE_DISCONNECT, ctx->tree_id, body, SMB2_TREE_DISCONNECT_REQUEST_SIZE, &resp, &resp_len);
        free(resp);
        ctx->tree_id = 0;
    }

    if (ctx->session_id) {
        resp = NULL;
        resp_len = 0;
        memset(body, 0, sizeof(body));
        wr16(body + 0, SMB2_LOGOFF_REQUEST_SIZE);
        smb_exchange(ctx, SMB2_LOGOFF, 0, body, SMB2_LOGOFF_REQUEST_SIZE, &resp, &resp_len);
        free(resp);
        ctx->session_id = 0;
    }

    if (ctx->sock != INVALID_SOCKET) {
        closesocket(ctx->sock);
        ctx->sock = INVALID_SOCKET;
    }
}

static int list_remote_pipes(smb_ctx *ctx, const char *host)
{
    sspi_ctx *sspi = NULL;
    uint8_t file_id[SMB2_FD_SIZE];
    int rc = -1;

    strncpy(ctx->server, host, sizeof(ctx->server) - 1);
    ctx->sock = INVALID_SOCKET;

    if (tcp_connect(ctx, host) != 0)
        return -1;

    sspi = sspi_init(ctx->server);
    if (!sspi) {
        set_error(ctx, "SSPI init failed");
        goto done;
    }

    if (smb2_negotiate(ctx) != 0)
        goto done;
    if (smb2_session_setup(ctx, sspi) != 0)
        goto done;
    if (smb2_tree_connect(ctx) != 0)
        goto done;

    internal_printf("[+] Connected using current credentials\n");
    if (strcmp(host, ctx->server) != 0)
        internal_printf("[+] Connected to \\\\%s\\IPC$ (resolved %s)\n", ctx->server, host);
    else
        internal_printf("[+] Connected to \\\\%s\\IPC$\n", ctx->server);
    internal_printf("[+] Pipe listing:\n");

    if (smb2_create_root(ctx, file_id) != 0)
        goto done;
    if (smb2_query_pipes(ctx, file_id) != 0)
        goto done;
    smb2_close(ctx, file_id);
    rc = 0;

done:
    sspi_free(sspi);
    smb2_disconnect(ctx);
    free(ctx->neg_token);
    ctx->neg_token = NULL;
    return rc;
}

static void print_error(smb_ctx *ctx, const char *context)
{
    if (ctx && ctx->last_error[0]) {
        if (strstr(ctx->last_error, "0xc000006d") || strstr(ctx->last_error, "0xC000006D"))
            BeaconPrintf(CALLBACK_ERROR, "Error: %s (%s) — logon failure (check domain credentials / access to this host)\n",
                         context, ctx->last_error);
        else
            BeaconPrintf(CALLBACK_ERROR, "Error: %s (%s)\n", context, ctx->last_error);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Error: %s\n", context);
    }
}

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser = {0};
    char *host = NULL;
    smb_ctx ctx;
    WSADATA wsa;

    BeaconDataParse(&parser, Buffer, Length);
    host = BeaconDataExtract(&parser, NULL);
    if (!host || !host[0]) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: remotepipelist <targetIP>\n");
        return;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Error: WSAStartup failed\n");
        return;
    }

    bofstart();

    memset(&ctx, 0, sizeof(ctx));
    ctx.sock = INVALID_SOCKET;
    ctx.last_error[0] = '\0';

    if (list_remote_pipes(&ctx, host) == 0) {
        printoutput(TRUE);
    } else {
        if (output) {
            intFree(output);
            output = NULL;
        }
        print_error(&ctx, "connect");
    }

    WSACleanup();
}
