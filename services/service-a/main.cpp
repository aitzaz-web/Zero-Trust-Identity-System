/**
 * Service-A: C++ mTLS service using OpenSSL.
 * - Listens on port 8080
 * - Requires client cert (mTLS)
 * - Verifies peer identity from cert SAN URI (SPIFFE)
 * - SIGHUP reloads certs (hot reload)
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <string>

static volatile int g_reload = 0;

void sig_handler(int sig) {
    if (sig == SIGHUP) g_reload = 1;
}

SSL_CTX* create_ssl_ctx(const char* cert_file, const char* key_file, const char* ca_file) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return nullptr;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_verify_depth(ctx, 2);

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) return nullptr;
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) return nullptr;
    if (SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) <= 0) return nullptr;

    return ctx;
}

std::string get_peer_spiffe_id(SSL* ssl) {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) return "";
    GENERAL_NAMES* names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (!names) { X509_free(cert); return ""; }
    std::string id;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
        if (name->type == GEN_URI) {
            const char* uri = (const char*)ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
            if (uri && strncmp(uri, "spiffe://", 9) == 0) {
                id = uri;
                break;
            }
        }
    }
    GENERAL_NAMES_free(names);
    X509_free(cert);
    return id;
}

int main(int argc, char* argv[]) {
    const char* cert = "/certs/cert.pem";
    const char* key = "/certs/key.pem";
    const char* ca = "/certs/chain.pem";
    int port = 8080;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) cert = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) ca = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    signal(SIGHUP, sig_handler);

    SSL_CTX* ctx = create_ssl_ctx(cert, key, ca);
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        return 1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 5);

    std::cout << "Service-A listening on port " << port << " (mTLS)\n";

    for (;;) {
        if (g_reload) {
            g_reload = 0;
            SSL_CTX* new_ctx = create_ssl_ctx(cert, key, ca);
            if (new_ctx) {
                SSL_CTX_free(ctx);
                ctx = new_ctx;
                std::cout << "Certs reloaded\n";
            }
        }

        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(listen_fd, &rd);
        struct timeval tv = {1, 0};
        if (select(listen_fd + 1, &rd, nullptr, nullptr, &tv) <= 0) continue;

        int client = accept(listen_fd, nullptr, nullptr);
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            std::cerr << "TLS handshake failed\n";
            SSL_free(ssl);
            close(client);
            continue;
        }
        std::string peer = get_peer_spiffe_id(ssl);
        std::cout << "Connected: " << peer << "\n";
        const char* resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK from service-a\n";
        SSL_write(ssl, resp, strlen(resp));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }
}
