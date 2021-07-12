//
// Created by lax on 11.07.21.
//

#ifndef LIBCOAP_COAP_IO_LOCAL_H
#define LIBCOAP_COAP_IO_LOCAL_H
#define END     ((uint8_t)0300)
#define ESC     0333
#define ESC_END 0334
#define ESC_ESC 0335
// ipv4
typedef struct pseudo_ip_hdr{ //TODO Frage, ob die length wichtig ist?
    uint8_t ip_ver;
    uint16_t ip_len;
    uint8_t ip_protocol;
    uint32_t ip_srcaddr;
    uint32_t ip_dstaddr;
} IP_HDR;

typedef struct pseudo_udp_hdr{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t udp_len;
} UDP_HDR;

void send_packet(const uint8_t *p, size_t len, void (*send_char)(uint8_t data));
int recv_packet(uint8_t *p, const uint8_t *data, size_t len);



#endif //LIBCOAP_COAP_IO_LOCAL_H
