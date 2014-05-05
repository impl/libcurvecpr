#ifndef __CURVECPR_PACKET_H
#define __CURVECPR_PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

struct curvecpr_packet_any {
    unsigned char id[8];
    unsigned char server_extension[16];
    unsigned char client_extension[16];
};

struct curvecpr_packet_hello {
    unsigned char id[8];
    unsigned char server_extension[16];
    unsigned char client_extension[16];
    unsigned char client_session_pk[32];
    unsigned char _[64];
    unsigned char nonce[8];
    unsigned char box[80];
};

struct curvecpr_packet_cookie_box {
    unsigned char _[32];
    unsigned char server_session_pk[32];
    unsigned char cookie[96];
};

struct curvecpr_packet_cookie {
    unsigned char id[8];
    unsigned char client_extension[16];
    unsigned char server_extension[16];
    unsigned char nonce[16];
    unsigned char box[144];
};

struct curvecpr_packet_initiate_box {
    unsigned char _[32];
    unsigned char client_global_pk[32];
    unsigned char nonce[16];
    unsigned char vouch[48];
    unsigned char server_domain_name[256];
    /* A message will follow. */
};

struct curvecpr_packet_initiate {
    unsigned char id[8];
    unsigned char server_extension[16];
    unsigned char client_extension[16];
    unsigned char client_session_pk[32];
    unsigned char cookie[96];
    unsigned char nonce[8];
    /* A boxed message will follow. */
};

struct curvecpr_packet_server_message {
    unsigned char id[8];
    unsigned char client_extension[16];
    unsigned char server_extension[16];
    unsigned char nonce[8];
    /* A boxed message will follow. */
};

struct curvecpr_packet_client_message {
    unsigned char id[8];
    unsigned char server_extension[16];
    unsigned char client_extension[16];
    unsigned char client_session_pk[32];
    unsigned char nonce[8];
    /* A boxed message will follow. */
};

#ifdef __cplusplus
}
#endif

#endif
