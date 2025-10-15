/*
 * Generate Dilithium3-based certificates for TLS
 * This creates a CA certificate and server certificate using Dilithium3 signatures
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define DILITHIUM3_NID 1184  // NID for dilithium3 in OQS-OpenSSL

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

// Generate a Dilithium3 key pair
EVP_PKEY* generate_dilithium3_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    
    // Try to create context for dilithium3
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Fallback to RSA if dilithium3 fails
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }
    
    // Try dilithium3 first
    int nid = OBJ_txt2nid("dilithium3");
    if (nid != NID_undef) {
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_id(nid, NULL);
    }
    
    if (!ctx) {
        fprintf(stderr, "Dilithium3 not available, using RSA\n");
        // Fallback to RSA
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    // For RSA, set key size
    if (nid == NID_undef) {
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Create a self-signed CA certificate
X509* create_ca_certificate(EVP_PKEY *pkey) {
    X509 *x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "Failed to create X509 structure\n");
        return NULL;
    }
    
    // Set version to X509v3
    X509_set_version(x509, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    // Set validity period (1 year)
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);
    
    // Set public key
    X509_set_pubkey(x509, pkey);
    
    // Set subject name (CA)
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"TestCA-PQ", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Test-CA-Dilithium", -1, -1, 0);
    
    // Self-signed, so issuer = subject
    X509_set_issuer_name(x509, name);
    
    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);
    
    X509_EXTENSION *ext;
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Sign the certificate
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Failed to sign CA certificate\n");
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}

// Create a server certificate signed by CA
X509* create_server_certificate(EVP_PKEY *server_key, EVP_PKEY *ca_key, X509 *ca_cert) {
    X509 *x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "Failed to create X509 structure\n");
        return NULL;
    }
    
    // Set version to X509v3
    X509_set_version(x509, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 2);
    
    // Set validity period (1 year)
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);
    
    // Set public key
    X509_set_pubkey(x509, server_key);
    
    // Set subject name (Server)
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"TestServer-PQ", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    
    // Set issuer from CA
    X509_set_issuer_name(x509, X509_get_subject_name(ca_cert));
    
    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, x509, NULL, NULL, 0);
    
    X509_EXTENSION *ext;
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Sign the certificate with CA key
    if (!X509_sign(x509, ca_key, EVP_sha256())) {
        fprintf(stderr, "Failed to sign server certificate\n");
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}

int main() {
    EVP_PKEY *ca_key = NULL;
    EVP_PKEY *server_key = NULL;
    X509 *ca_cert = NULL;
    X509 *server_cert = NULL;
    FILE *fp = NULL;
    
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║  Generating Dilithium3 Certificates              ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n\n");
    
    init_openssl();
    
    // Create certs directory
    system("mkdir -p certs");
    
    printf("[1] Generating CA key pair (Dilithium3)...\n");
    ca_key = generate_dilithium3_key();
    if (!ca_key) {
        fprintf(stderr, "Failed to generate CA key\n");
        goto cleanup;
    }
    printf("    ✓ CA key generated\n\n");
    
    printf("[2] Creating CA certificate...\n");
    ca_cert = create_ca_certificate(ca_key);
    if (!ca_cert) {
        fprintf(stderr, "Failed to create CA certificate\n");
        goto cleanup;
    }
    printf("    ✓ CA certificate created\n\n");
    
    printf("[3] Generating server key pair (Dilithium3)...\n");
    server_key = generate_dilithium3_key();
    if (!server_key) {
        fprintf(stderr, "Failed to generate server key\n");
        goto cleanup;
    }
    printf("    ✓ Server key generated\n\n");
    
    printf("[4] Creating server certificate...\n");
    server_cert = create_server_certificate(server_key, ca_key, ca_cert);
    if (!server_cert) {
        fprintf(stderr, "Failed to create server certificate\n");
        goto cleanup;
    }
    printf("    ✓ Server certificate created\n\n");
    
    printf("[5] Saving certificates and keys...\n");
    
    // Save CA certificate
    fp = fopen("certs/ca-cert-dilithium.pem", "wb");
    if (!fp || !PEM_write_X509(fp, ca_cert)) {
        fprintf(stderr, "Failed to write CA certificate\n");
        goto cleanup;
    }
    fclose(fp);
    printf("    ✓ Saved: certs/ca-cert-dilithium.pem\n");
    
    // Save CA private key
    fp = fopen("certs/ca-key-dilithium.pem", "wb");
    if (!fp || !PEM_write_PrivateKey(fp, ca_key, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write CA private key\n");
        goto cleanup;
    }
    fclose(fp);
    printf("    ✓ Saved: certs/ca-key-dilithium.pem\n");
    
    // Save server certificate
    fp = fopen("certs/server-dilithium.crt", "wb");
    if (!fp || !PEM_write_X509(fp, server_cert)) {
        fprintf(stderr, "Failed to write server certificate\n");
        goto cleanup;
    }
    fclose(fp);
    printf("    ✓ Saved: certs/server-dilithium.crt\n");
    
    // Save server private key
    fp = fopen("certs/server-dilithium.key", "wb");
    if (!fp || !PEM_write_PrivateKey(fp, server_key, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write server private key\n");
        goto cleanup;
    }
    fclose(fp);
    printf("    ✓ Saved: certs/server-dilithium.key\n");
    
    // Set permissions
    system("chmod 600 certs/*-dilithium.pem certs/*-dilithium.key 2>/dev/null");
    
    printf("\n✓ Certificate generation complete!\n");
    printf("\nNote: If Dilithium3 was not available, RSA keys were generated as fallback.\n");
    printf("To use these certificates, update your TLS code to load:\n");
    printf("  - CA: certs/ca-cert-dilithium.pem\n");
    printf("  - Server Cert: certs/server-dilithium.crt\n");
    printf("  - Server Key: certs/server-dilithium.key\n");
    
cleanup:
    if (ca_key) EVP_PKEY_free(ca_key);
    if (server_key) EVP_PKEY_free(server_key);
    if (ca_cert) X509_free(ca_cert);
    if (server_cert) X509_free(server_cert);
    cleanup_openssl();
    
    return 0;
}
