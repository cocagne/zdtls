#ifndef __ZDTLS_SSL_HELPERS_H__
#define __ZDTLS_SSL_HELPERS_H__

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// display error message and abort program
static void err(char * msg)
{
   fprintf(stderr, "%s\n", msg);
   exit(1);
}


// print cipher information
static void show_cipher(SSL* ssl)
{
   SSL_CIPHER * c = SSL_get_current_cipher(ssl);
   printf("Using cipher: %s\n", SSL_CIPHER_get_name(c));
}


// load cert and key files into the supplied SSL context
static void load_certs(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

// print certificate information
static void show_certs(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}



#endif // __ZDTLS_SSL_HELPERS_H__
