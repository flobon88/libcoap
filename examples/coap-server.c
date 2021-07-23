/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 *
 * Copyright (C) 2010--2021 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef R_OK
#define R_OK 4
#endif
static char* strndup(const char* s1, size_t n)
{
  char* copy = (char*)malloc(n + 1);
  if (copy) {
    memcpy(copy, s1, n);
    copy[n] = 0;
  }
  return copy;
};
#include <io.h>
#define access _access
#define fileno _fileno
#else

#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#endif

#ifndef SERVER_CAN_PROXY
#define SERVER_CAN_PROXY 1
#endif

/* Need to refresh time once per sec */
#define COAP_RESOURCE_CHECK_TIME 1

#include <coap3/coap.h>

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

/* temporary storage for dynamic resource representations */
static int quit = 0;

/*
 * For PKI, if one or more of cert_file, key_file and ca_file is in PKCS11 URI
 * format, then the remainder of cert_file, key_file and ca_file are treated
 * as being in DER format to provide consistency across the underlying (D)TLS
 * libraries.
 */
/*static char *cert_file = NULL;  certificate and optional private key in PEM,
                                  or PKCS11 URI*/
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM,
                                  DER or PKCS11 URI */
static uint8_t *key_mem = NULL; /* private key in PEM_BUF */
static int verify_peer_cert = 1; /* PKI granularity - by default set */
#define MAX_KEY   64 /* Maximum length of a pre-shared key in bytes. */
static uint8_t *key = NULL;
static ssize_t key_length = 0;
int key_defined = 0;
static const char *hint = NULL;


typedef struct psk_sni_def_t {
    char *sni_match;
    coap_bin_const_t *new_key;
    coap_bin_const_t *new_hint;
} psk_sni_def_t;

typedef struct valid_psk_snis_t {
    size_t count;
    psk_sni_def_t *psk_sni_list;
} valid_psk_snis_t;

static valid_psk_snis_t valid_psk_snis = {0, NULL};

typedef struct id_def_t {
    char *hint_match;
    coap_bin_const_t *identity_match;
    coap_bin_const_t *new_key;
} id_def_t;

typedef struct valid_ids_t {
    size_t count;
    id_def_t *id_list;
} valid_ids_t;

static valid_ids_t valid_ids = {0, NULL};
typedef struct pki_sni_def_t {
    char *sni_match;
    char *new_cert;
    char *new_ca;
} pki_sni_def_t;

typedef struct valid_pki_snis_t {
    size_t count;
    pki_sni_def_t *pki_sni_list;
} valid_pki_snis_t;

static valid_pki_snis_t valid_pki_snis = {0, NULL};

typedef struct transient_value_t {
    coap_binary_t *value;
    size_t ref_cnt;
} transient_value_t;

static transient_value_t *example_data_value = NULL;
static int example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum COAP_UNUSED) {
    quit = 1;
}

static const coap_dtls_spsk_info_t *
verify_psk_sni_callback(const char *sni,
                        coap_session_t *c_session COAP_UNUSED,
                        void *arg COAP_UNUSED
) {
    static coap_dtls_spsk_info_t psk_info;

    /* Preset with the defined keys */
    memset(&psk_info, 0, sizeof(psk_info));
    psk_info.hint.s = (const uint8_t *) hint;
    psk_info.hint.length = hint ? strlen(hint) : 0;
    psk_info.key.s = key;
    psk_info.key.length = key_length;
    if (sni) {
        size_t i;
        coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
        for (i = 0; i < valid_psk_snis.count; i++) {
            /* Test for identity match to change key */
            if (strcasecmp(sni,
                           valid_psk_snis.psk_sni_list[i].sni_match) == 0) {
                coap_log(LOG_INFO, "Switching to using '%.*s' hint + '%.*s' key\n",
                         (int) valid_psk_snis.psk_sni_list[i].new_hint->length,
                         valid_psk_snis.psk_sni_list[i].new_hint->s,
                         (int) valid_psk_snis.psk_sni_list[i].new_key->length,
                         valid_psk_snis.psk_sni_list[i].new_key->s);
                psk_info.hint = *valid_psk_snis.psk_sni_list[i].new_hint;
                psk_info.key = *valid_psk_snis.psk_sni_list[i].new_key;
                break;
            }
        }
    } else {
        coap_log(LOG_DEBUG, "SNI not requested\n");
    }
    return &psk_info;
}

static const coap_bin_const_t *
verify_id_callback(coap_bin_const_t *identity,
                   coap_session_t *c_session,
                   void *arg COAP_UNUSED
) {
    static coap_bin_const_t psk_key;
    const coap_bin_const_t *s_psk_hint = coap_session_get_psk_hint(c_session);
    const coap_bin_const_t *s_psk_key;
    size_t i;

    coap_log(LOG_INFO, "Identity '%.*s' requested, current hint '%.*s'\n", (int) identity->length,
             identity->s,
             s_psk_hint ? (int) s_psk_hint->length : 0,
             s_psk_hint ? (const char *) s_psk_hint->s : "");

    for (i = 0; i < valid_ids.count; i++) {
        /* Check for hint match */
        if (s_psk_hint &&
            strcmp((const char *) s_psk_hint->s,
                   valid_ids.id_list[i].hint_match)) {
            continue;
        }
        /* Test for identity match to change key */
        if (coap_binary_equal(identity, valid_ids.id_list[i].identity_match)) {
            coap_log(LOG_INFO, "Switching to using '%.*s' key\n",
                     (int) valid_ids.id_list[i].new_key->length,
                     valid_ids.id_list[i].new_key->s);
            return valid_ids.id_list[i].new_key;
        }
    }

    s_psk_key = coap_session_get_psk_key(c_session);
    if (s_psk_key) {
        /* Been updated by SNI callback */
        psk_key = *s_psk_key;
        return &psk_key;
    }

    /* Just use the defined key for now */
    psk_key.s = key;
    psk_key.length = key_length;
    return &psk_key;
}

static coap_dtls_spsk_t *
setup_spsk(void) {
    static coap_dtls_spsk_t dtls_spsk;

    memset(&dtls_spsk, 0, sizeof(dtls_spsk));
    dtls_spsk.version = COAP_DTLS_SPSK_SETUP_VERSION;
    dtls_spsk.validate_id_call_back = valid_ids.count ?
                                      verify_id_callback : NULL;
    dtls_spsk.validate_sni_call_back = valid_psk_snis.count ?
                                       verify_psk_sni_callback : NULL;
    dtls_spsk.psk_info.hint.s = (const uint8_t *) hint;
    dtls_spsk.psk_info.hint.length = hint ? strlen(hint) : 0;
    dtls_spsk.psk_info.key.s = key;
    dtls_spsk.psk_info.key.length = key_length;
    return &dtls_spsk;
}

static void
fill_keystore(coap_context_t *ctx) {

    if (key_defined) {
        coap_dtls_spsk_t *dtls_spsk = setup_spsk();

        coap_context_set_psk2(ctx, dtls_spsk);
    }
}

static void
usage(const char *program, const char *version) {
    const char *p;
    char buffer[72];
    const char *lib_version = coap_package_version();

    p = strrchr(program, '/');
    if (p)
        program = ++p;

    fprintf(stderr, "%s v%s -- a small CoAP implementation\n"
                    "(c) 2010,2011,2015-2021 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
                    "%s\n"
                    "%s\n", program, version, lib_version,
            coap_string_tls_version(buffer, sizeof(buffer)));
    fprintf(stderr, "%s\n", coap_string_tls_support(buffer, sizeof(buffer)));
    fprintf(stderr, "\n"
                    "Usage: %s [-d max] [-e] [-g group] [-G group_if] [-l loss] [-p port]\n"
                    "\t\t[-v num] [-A address] [-L value] [-N]\n"
                    "\t\t[-P scheme://address[:port],name1[,name2..]]\n"
                    "\t\t[[-h hint] [-i match_identity_file] [-k key]\n"
                    "\t\t[-s match_psk_sni_file] [-u user]]\n"
                    "\t\t[[-c certfile] [-j keyfile] [-m] [-n] [-C cafile]\n"
                    "\t\t[-J pkcs11_pin] [-M rpk_file] [-R trust_casfile]\n"
                    "\t\t[-S match_pki_sni_file]]\n"
                    "General Options\n"
                    "\t-d max \t\tAllow dynamic creation of up to a total of max\n"
                    "\t       \t\tresources. If max is reached, a 4.06 code is returned\n"
                    "\t       \t\tuntil one of the dynamic resources has been deleted\n"
                    "\t-e     \t\tEcho back the data sent with a PUT\n"
                    "\t-g group\tJoin the given multicast group\n"
                    "\t       \t\tNote: DTLS over multicast is not currently supported\n"
                    "\t-G group_if\tUse this interface for listening for the multicast\n"
                    "\t       \t\tgroup. This can be different from the implied interface\n"
                    "\t       \t\tif the -A option is used\n"
                    "\t-l list\t\tFail to send some datagrams specified by a comma\n"
                    "\t       \t\tseparated list of numbers or number ranges\n"
                    "\t       \t\t(for debugging only)\n"
                    "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
                    "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
                    "\t       \t\t(for debugging only)\n"
                    "\t-p port\t\tListen on specified port for UDP and TCP. If (D)TLS is\n"
                    "\t       \t\tenabled, then the coap-server will also listen on\n"
                    "\t       \t\t 'port'+1 for DTLS and TLS.  The default port is 5683\n"
                    "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
                    "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL\n"
                    "\t       \t\tlogging\n"
                    "\t-A address\tInterface address to bind to\n"
                    "\t-L value\tSum of one or more COAP_BLOCK_* flag valuess for block\n"
                    "\t       \t\thandling methods. Default is 1 (COAP_BLOCK_USE_LIBCOAP)\n"
                    "\t       \t\t(Sum of one or more of 1,2 and 4)\n"
                    "\t-N     \t\tMake \"observe\" responses NON-confirmable. Even if set\n"
                    "\t       \t\tevery fifth response will still be sent as a confirmable\n"
                    "\t       \t\tresponse (RFC 7641 requirement)\n", program);
    fprintf(stderr,
            "\t-P scheme://address[:port],name1[,name2[,name3..]]\tScheme, address,\n"
            "\t       \t\toptional port of how to connect to the next proxy server\n"
            "\t       \t\tand one or more names (comma separated) that this proxy\n"
            "\t       \t\tserver is known by. If the hostname of the incoming proxy\n"
            "\t       \t\trequest matches one of these names, then this server is\n"
            "\t       \t\tconsidered to be the final endpoint. If\n"
            "\t       \t\tscheme://address[:port] is not defined before the leading\n"
            "\t       \t\t, (comma) of the first name, then the ongoing connection\n"
            "\t       \t\twill be a direct connection.\n"
            "\t       \t\tScheme is one of coap, coaps, coap+tcp and coaps+tcp\n"
            "PSK Options (if supported by underlying (D)TLS library)\n"
            "\t-h hint\t\tIdentity Hint to send. Default is CoAP. Zero length is\n"
            "\t       \t\tno hint\n"
            "\t-i match_identity_file\n"
            "\t       \t\tThis is a file that contains one or more lines of\n"
            "\t       \t\tIdentity Hints and (user) Identities to match for\n"
            "\t       \t\ta different new Pre-Shared Key (PSK) (comma separated)\n"
            "\t       \t\tto be used. E.g., per line\n"
            "\t       \t\t hint_to_match,identity_to_match,use_key\n"
            "\t       \t\tNote: -k still needs to be defined for the default case\n"
            "\t       \t\tNote: A match using the -s option may mean that the\n"
            "\t       \t\tcurrent Identity Hint is different to that defined by -h\n"
            "\t-k key \t\tPre-Shared Key. This argument requires (D)TLS with PSK\n"
            "\t       \t\tto be available. This cannot be empty if defined.\n"
            "\t       \t\tNote that both -c and -k need to be defined for both\n"
            "\t       \t\tPSK and PKI to be concurrently supported\n"
            "\t-s match_psk_sni_file\n"
            "\t       \t\tThis is a file that contains one or more lines of\n"
            "\t       \t\treceived Subject Name Identifier (SNI) to match to use\n"
            "\t       \t\ta different Identity Hint and associated Pre-Shared Key\n"
            "\t       \t\t(PSK) (comma separated) instead of the '-h hint' and\n"
            "\t       \t\t'-k key' options. E.g., per line\n"
            "\t       \t\t sni_to_match,use_hint,with_key\n"
            "\t       \t\tNote: -k still needs to be defined for the default case\n"
            "\t       \t\tif there is not a match\n"
            "\t       \t\tNote: The associated Pre-Shared Key will get updated if\n"
            "\t       \t\tthere is also a -i match.  The update checking order is\n"
            "\t       \t\t-s followed by -i\n"
            "\t-u user\t\tUser identity for pre-shared key mode (only used if\n"
            "\t       \t\toption -P is set)\n"
    );
    fprintf(stderr,
            "PKI Options (if supported by underlying (D)TLS library)\n"
            "\tNote: If any one of '-c certfile', '-j keyfile' or '-C cafile' is in\n"
            "\tPKCS11 URI naming format (pkcs11: prefix), then any remaining non\n"
            "\tPKCS11 URI file definitions have to be in DER, not PEM, format.\n"
            "\tOtherwise all of '-c certfile', '-j keyfile' or '-C cafile' are in\n"
            "\tPEM format.\n\n"
            "\t-c certfile\tPEM file or PKCS11 URI for the certificate. The private\n"
            "\t       \t\tkey can also be in the PEM file, or has the same PKCS11\n"
            "\t       \t\tURI. If not, the private key is defined by '-j keyfile'.\n"
            "\t       \t\tNote that both -c and -k need to be defined for both\n"
            "\t       \t\tPSK and PKI to be concurrently supported\n"
            "\t-j keyfile\tPEM file or PKCS11 URI for the private key for the\n"
            "\t       \t\tcertificate in '-c certfile' if the parameter is\n"
            "\t       \t\tdifferent from certfile in '-c certfile'\n"
            "\t-m     \t\tUse COAP_PKI_KEY_PEM_BUF instead of COAP_PKI_KEY_PEM i/f\n"
            "\t       \t\tby reading into memory the Cert / CA file (for testing)\n"
            "\t-n     \t\tDisable remote peer certificate checking. This gives\n"
            "\t       \t\tclients the ability to use PKI, but without any defined\n"
            "\t       \t\tcertificates\n"
            "\t-C cafile\tPEM file or PKCS11 URI that contains a list of one or\n"
            "\t       \t\tmore CAs that are to be passed to the client for the\n"
            "\t       \t\tclient to determine what client certificate to use.\n"
            "\t       \t\tNormally, this list of CAs would be the root CA and and\n"
            "\t       \t\tany intermediate CAs. Ideally the server certificate\n"
            "\t       \t\tshould be signed by the same CA so that mutual\n"
            "\t       \t\tauthentication can take place. The contents of cafile\n"
            "\t       \t\tare added to the trusted store of root CAs.\n"
            "\t       \t\tUsing the -C or -R options will will trigger the\n"
            "\t       \t\tvalidation of the client certificate unless overridden\n"
            "\t       \t\tby the -n option\n"
            "\t-J pkcs11_pin\tThe user pin to unlock access to the PKCS11 token\n"
            "\t-M rpk_file\tRaw Public Key (RPK) PEM file or PKCS11 URI that\n"
            "\t       \t\tcontains both PUBLIC KEY and PRIVATE KEY or just\n"
            "\t       \t\tEC PRIVATE KEY. (GnuTLS and TinyDTLS(PEM) support only).\n"
            "\t       \t\t'-C cafile' or '-R trust_casfile' are not required\n"
            "\t-R trust_casfile\tPEM file containing the set of trusted root CAs\n"
            "\t       \t\tthat are to be used to validate the client certificate.\n"
            "\t       \t\tAlternatively, this can point to a directory containing\n"
            "\t       \t\ta set of CA PEM files.\n"
            "\t       \t\tUsing '-R trust_casfile' disables common CA mutual\n"
            "\t       \t\tauthentication which can only be done by using\n"
            "\t       \t\t'-C cafile'.\n"
            "\t       \t\tUsing the -C or -R options will will trigger the\n"
            "\t       \t\tvalidation of the client certificate unless overridden\n"
            "\t       \t\tby the -n option\n"
            "\t-S match_pki_sni_file\n"
            "\t       \t\tThis option denotes a file that contains one or more\n"
            "\t       \t\tlines of Subject Name Identifier (SNI) to match for new\n"
            "\t       \t\tCert file and new CA file (comma separated) to be used.\n"
            "\t       \t\tE.g., per line\n"
            "\t       \t\t sni_to_match,new_cert_file,new_ca_file\n"
            "\t       \t\tNote: -c and -C still need to be defined for the default\n"
            "\t       \t\tcase\n"
    );
}

static coap_context_t *
get_context(const char *node, const char *port) {
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    ctx = coap_new_context(NULL);
    if (!ctx) {
        return NULL;
    }
    /* Need PKI/RPK/PSK set up before we set up (D)TLS endpoints */
    fill_keystore(ctx);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    /*s = getaddrinfo(node, port, &hints, &result);
    if ( s != 0 ) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      coap_free_context(ctx);
      return NULL;
    }*/
    coap_address_t addr, addrs;
    coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL;
    coap_address_init(&addr);
    addr.size = (socklen_t) strlen(node);
    addr.addr.su.sun_family = AF_UNIX;
    memcpy(&addr.addr.su.sun_path, node, addr.size);
    ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
    if (ep_udp) {
        if (coap_dtls_is_supported() && (key_defined)) {
            ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
            if (!ep_dtls)
                coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
        }
    } else {
        coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
    }
    /*if (coap_tcp_is_supported()) {
        coap_endpoint_t *ep_tcp;
        ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
        if (ep_tcp) {
            if (coap_tls_is_supported() && (key_defined)) {
                coap_endpoint_t *ep_tls;
                ep_tls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_TLS);
                if (!ep_tls)
                    coap_log(LOG_CRIT, "cannot create TLS endpoint\n");
            }
        } else {
            coap_log(LOG_CRIT, "cannot create TCP endpoint\n");
        }
    }*/
    if (ep_udp)
        goto finish;


    /* iterate through results until success */
    for (rp = result; rp != NULL && 0; rp = rp->ai_next) {
        //coap_address_t addr, addrs;
        //coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL;

        if (rp->ai_addrlen <= (socklen_t) sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = (socklen_t) rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
            addrs = addr;
            if (addr.addr.sa.sa_family == AF_INET) {
                uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
                addrs.addr.sin.sin_port = htons(temp);
            } else if (addr.addr.sa.sa_family == AF_INET6) {
                uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
                addrs.addr.sin6.sin6_port = htons(temp);
            } else {
                goto finish;
            }

            ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
            if (ep_udp) {
                if (coap_dtls_is_supported() && (key_defined)) {
                    ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
                    if (!ep_dtls)
                        coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
                }
            } else {
                coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
                continue;
            }
            if (coap_tcp_is_supported()) {
                coap_endpoint_t *ep_tcp;
                ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
                if (ep_tcp) {
                    if (coap_tls_is_supported() && (key_defined)) {
                        coap_endpoint_t *ep_tls;
                        ep_tls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_TLS);
                        if (!ep_tls)
                            coap_log(LOG_CRIT, "cannot create TLS endpoint\n");
                    }
                } else {
                    coap_log(LOG_CRIT, "cannot create TCP endpoint\n");
                }
            }
            if (ep_udp)
                goto finish;
        }
    }

    fprintf(stderr, "no context available for interface '%s'\n", node);
    coap_free_context(ctx);
    ctx = NULL;

    finish:
    return ctx;
}

static ssize_t
cmdline_read_key(char *arg, unsigned char **buf, size_t maxlen) {
    size_t len = strnlen(arg, 64);
    if (len) {
        *buf = (unsigned char *) arg;
        return len;
    }
    /* Need at least one byte for the pre-shared key */
    coap_log(LOG_CRIT, "Invalid Pre-Shared Key specified\n");
    return -1;
}


int
main(int argc, char **argv) {
    coap_context_t *ctx;
    char *group = NULL;
    char addr_str[NI_MAXHOST] = "/tmp/coap_unix_socket.socket";
    char port_str[NI_MAXSERV] = "5683";
    int opt;
    coap_log_t log_level = LOG_WARNING;
    unsigned wait_ms;
    int coap_fd;
    fd_set m_readfds;
    int nfds = 0;
    size_t i;
    uint16_t cache_ignore_options[] = {COAP_OPTION_BLOCK1,
                                       COAP_OPTION_BLOCK2,
            /* See https://tools.ietf.org/html/rfc7959#section-2.10 */
                                       COAP_OPTION_MAXAGE,
            /* See https://tools.ietf.org/html/rfc7959#section-2.10 */
                                       COAP_OPTION_IF_NONE_MATCH};
#ifndef _WIN32
    struct sigaction sa;
#endif

    //disable hint
    hint = NULL;

    while ((opt = getopt(argc, argv, "g:k:np:v:A:")) != -1) {
        switch (opt) {
            case 'A' :
                strncpy(addr_str, optarg, NI_MAXHOST - 1);
                addr_str[NI_MAXHOST - 1] = '\0';
                break;
            case 'g' :
                group = optarg;
                break;
            case 'k' :
                key_length = cmdline_read_key(optarg, &key, MAX_KEY);
                if (key_length < 0) {
                    break;
                }
                key_defined = 1;
                break;
            case 'p' :
                strncpy(port_str, optarg, NI_MAXSERV - 1);
                port_str[NI_MAXSERV - 1] = '\0';
                break;
            case 'v' :
                log_level = strtol(optarg, NULL, 10);
                break;
            default:
                usage(argv[0], LIBCOAP_PACKAGE_VERSION);
                exit(1);
        }
    }

    coap_startup();
    coap_dtls_set_log_level(log_level);
    coap_set_log_level(log_level);

    ctx = get_context(addr_str, port_str);
    if (!ctx)
        return -1;

    /* Define the options to ignore when setting up cache-keys */
    coap_cache_ignore_options(ctx, cache_ignore_options,
                              sizeof(cache_ignore_options) / sizeof(cache_ignore_options[0]));
    /* join multicast group if requested at command line */
    if (group)
        coap_join_mcast_group(ctx, group);

    coap_fd = coap_context_get_coap_fd(ctx);
    if (coap_fd != -1) {
        /* if coap_fd is -1, then epoll is not supported within libcoap */
        FD_ZERO(&m_readfds);
        FD_SET(coap_fd, &m_readfds);
        nfds = coap_fd + 1;
    }

#ifdef _WIN32
    signal(SIGINT, handle_sigint);
#else
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* So we do not exit on a SIGPIPE */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
#endif

    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

    while (!quit) {
        int result;

        if (coap_fd != -1) {
            /*
             * Using epoll.  It is more usual to call coap_io_process() with wait_ms
             * (as in the non-epoll branch), but doing it this way gives the
             * flexibility of potentially working with other file descriptors that
             * are not a part of libcoap.
             */
            fd_set readfds = m_readfds;
            struct timeval tv;
            coap_tick_t begin, end;

            coap_ticks(&begin);

            tv.tv_sec = wait_ms / 1000;
            tv.tv_usec = (wait_ms % 1000) * 1000;
            /* Wait until any i/o takes place or timeout */
            result = select(nfds, &readfds, NULL, NULL, &tv);
            if (result == -1) {
                if (errno != EAGAIN) {
                    coap_log(LOG_DEBUG, "select: %s (%d)\n", coap_socket_strerror(), errno);
                    break;
                }
            }
            if (result > 0) {
                if (FD_ISSET(coap_fd, &readfds)) {
                    result = coap_io_process(ctx, COAP_IO_NO_WAIT);
                }
            }
            if (result >= 0) {
                coap_ticks(&end);
                /* Track the overall time spent in select() and coap_io_process() */
                result = (int) (end - begin);
            }
        } else {
            /*
             * epoll is not supported within libcoap
             *
             * result is time spent in coap_io_process()
             */
            result = coap_io_process(ctx, wait_ms);
        }
        if (result < 0) {
            break;
        } else if (result && (unsigned) result < wait_ms) {
            /* decrement if there is a result wait time returned */
            wait_ms -= result;
        } else {
            /*
             * result == 0, or result >= wait_ms
             * (wait_ms could have decremented to a small value, below
             * the granularity of the timer in coap_io_process() and hence
             * result == 0)
             */
            wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
        }
    }

    coap_free(key_mem);
    for (i = 0; i < valid_psk_snis.count; i++) {
        free(valid_psk_snis.psk_sni_list[i].sni_match);
        coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_hint);
        coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_key);
    }
    if (valid_psk_snis.count)
        free(valid_psk_snis.psk_sni_list);

    for (i = 0; i < valid_ids.count; i++) {
        free(valid_ids.id_list[i].hint_match);
        coap_delete_bin_const(valid_ids.id_list[i].identity_match);
        coap_delete_bin_const(valid_ids.id_list[i].new_key);
    }
    if (valid_ids.count)
        free(valid_ids.id_list);

    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}
