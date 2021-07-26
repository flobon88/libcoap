#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <bits/stdint-uintn.h>
//#include "connection.h"

#define SOCKET_NAME "/tmp/coap_socket.socket_client"
#define SOCKET_NAME_SERVER "/tmp/coap_unix_socket.socket"
#define BUFFER_SIZE 12

/*int
main(int argc, char *argv[])
{
    struct sockaddr_un addr;
    int i;
    int ret;
    int data_socket;
    char buffer[BUFFER_SIZE];


    data_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (data_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }



    memset(&addr, 0, sizeof(struct sockaddr_un));


    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);

    ret = connect (data_socket, (const struct sockaddr *) &addr,
                   sizeof(struct sockaddr_un));
    if (ret == -1) {
        fprintf(stderr, "The server is down.\n");
        exit(EXIT_FAILURE);
    }


    for (i = 1; i < argc; ++i) {
        ret = write(data_socket, argv[i], strlen(argv[i]) + 1);
        if (ret == -1) {
            perror("write");
            break;
        }
    }


    strcpy (buffer, "END");
    ret = write(data_socket, buffer, strlen(buffer) + 1);
    if (ret == -1) {
        perror("write");
        exit(EXIT_FAILURE);
    }


    ret = read(data_socket, buffer, BUFFER_SIZE);
    if (ret == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }


    buffer[BUFFER_SIZE - 1] = 0;

    printf("Result = %s\n", buffer);


    close(data_socket);

    exit(EXIT_SUCCESS);
}*/
#define SLIP_END     ((uint8_t)0300)
#define SLIP_ESC     ((uint8_t)0333)
#define SLIP_ESC_END ((uint8_t)0334)
#define SLIP_ESC_ESC ((uint8_t)0335)
size_t send_packet(uint8_t *p, const uint8_t *data, size_t len) {
    size_t send = 0;
    p[send++] = SLIP_END;

    while (len--) {
        switch (*data) {
            case SLIP_END:
                p[send++] = SLIP_ESC;
                p[send++] = SLIP_ESC_END;
                break;
            case SLIP_ESC:
                p[send++] = SLIP_ESC;
                p[send++] = SLIP_ESC_ESC;
                break;
            default:
                p[send++] = *data;
        }

        data++;
    }
    p[send] = SLIP_END;
    return send;
}

int
main(int argc, char *argv[]) {
    struct sockaddr_un svaddr, claddr, server_addr;
    int sfd, j;
    size_t msgLen = 25;
    ssize_t numBytes;
    char resp[108];

    if (argc < 2 || strcmp(argv[1], "--help") == 0)
        printf("%s msg...\n", argv[0]);

    /* Create client socket; bind to unique pathname (based on PID) */

    sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sfd == -1)
        printf("socket failed");

    memset(&claddr, 0, sizeof(struct sockaddr_un));
    claddr.sun_family = AF_UNIX;
    snprintf(claddr.sun_path, sizeof(claddr.sun_path),
             "/tmp/ud_ucase_cl.%ld", (long) getpid());

    if (bind(sfd, (struct sockaddr *) &claddr, sizeof(struct sockaddr_un)) == -1)
        printf("bind failed");

    /* Construct address of server */
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_NAME_SERVER, 104);
    memset(&svaddr, 0, sizeof(struct sockaddr_un));
    svaddr.sun_family = AF_UNIX;
    strncpy(svaddr.sun_path, SOCKET_NAME, sizeof(svaddr.sun_path) - 1);

    if (connect(sfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        printf("Konnte nicht verbinden");
    }

    /* Send messages to server; echo responses on stdout */

    //for (j = 1; j < argc; j++) {
    //msgLen = strlen(argv[j]);       /* May be longer than BUF_SIZE */
    uint8_t msg[msgLen];
    msg[0] = '\004';
    msg[1] = 192;
    msg[2] = 168;
    msg[3] = 178;
    msg[4] = 16;
    msg[5] = 192;
    msg[6] = 168;
    msg[7] = 178;
    msg[8] = 12;
    msg[9] = '\002';
    msg[10] = '\001';
    msg[11] = 4;
    msg[12] = 3;
    msg[13] = 0x55;
    msg[14] = 0x73;
    msg[15] = 0x12;
    msg[16] = 0x34;
    for(int i = 17; i < 22; i++){
        msg[i] = 'a' + i;
    }
    msg[22] = '\000';
    msg[23] = 0xc1;
    msg[24] = 0x00;
    uint32_t packet_len = 3 * msgLen;
    uint8_t packet[packet_len];
    memset(packet,'\000',packet_len);
    uint32_t length = send_packet(packet,msg,msgLen);
    if (sendto(sfd, packet, length, 0, (struct sockaddr *) &server_addr,
               sizeof(struct sockaddr_un)) != length)
        printf("sendto failed");
    /*if (send(sfd, argv[j], msgLen,0) != msgLen)
        printf("sendto failed");*/

    numBytes = recvfrom(sfd, resp, 104, 0, NULL, NULL);
    /*Or equivalently: numBytes = recv(sfd, resp, BUF_SIZE, 0);
                    or: numBytes = read(sfd, resp, 104);*/
    if (numBytes == -1)
        printf("recvfrom failed");
    printf("Response %d: %.*s\n", j, (int) numBytes, resp);
    //}

    remove(claddr.sun_path);            /* Remove client socket pathname */
    exit(EXIT_SUCCESS);
}
