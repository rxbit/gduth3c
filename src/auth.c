#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <openssl/md5.h>
#include "auth.h"

const unsigned char nearest_mac[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
const unsigned char version[32] = "\006\007b2BcGRxWNXQtTExmJgR5fSpGmRU=  ";
unsigned char md5buf[64] = {0};
char ifname[16] = "eth0";
char username[16] = "";
char password[16] = "";
char dhcpscript[32] = "";
int client_fd;

struct packet packet_send = {
    .x_version = EAPOL_VERSION
}, packet_recv;

int auth_init()
{
    struct sockaddr_ll addr;
    struct ifreq ifr;
    if((client_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_TYPE_PAE))) < 0) {
        return AUTH_ERR;
    }

    memset(&ifr, 0 , sizeof(ifr));
    strncpy(ifr.ifr_name, ifname , sizeof(ifr.ifr_name));

    if (ioctl(client_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("Interface IO error");
        return AUTH_ERR;
    };

    if ((ifr.ifr_flags & IFF_UP) == 0) {
        fprintf(stderr,"Interface is not up\n");
        return AUTH_ERR;
    }
/*
    if ((ifr.ifr_flags & IFF_RUNNING) == 0) {
       fprintf(stderr,"No cable\n");
        return AUTH_ERR;
    }
*/
    ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
    if (ioctl(client_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Failed set to promiscuous mode");
        return AUTH_ERR;
    }

    if (ioctl(client_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("hwaddr error");
        return AUTH_ERR;
    }

    memcpy(packet_send.src_mac, ifr.ifr_hwaddr.sa_data, 6);
    packet_send.proto = htons(ETH_TYPE_PAE);

    if (ioctl(client_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("io error");
        return AUTH_ERR;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_TYPE_PAE);
    addr.sll_ifindex = ifr.ifr_ifindex;

    if(bind(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return AUTH_ERR;
    };

    return 0;
}

void set_socket_timeout(time_t sec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = 50000;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
}

int send_start_logoff(int type)
{
    memcpy(packet_send.dst_mac, nearest_mac, 6);
    packet_send.x_type = type;
    packet_send.x_length = 0;
    return send(client_fd, &packet_send, 18, 0);
}

int send_start()
{
    return send_start_logoff(EAPOL_START);
}

int send_logoff()
{
    return send_start_logoff(EAPOL_LOGOFF);
}


int send_id()
{
    packet_send.x_type = EAPOL_EAPPACKET;
    packet_send.x_length = htons(5 + 32 + strlen(username));
    packet_send.eap_code = EAP_RESPONSE;
    packet_send.eap_type = EAP_TYPE_ID;
    packet_send.eap_length = packet_send.x_length;
    memcpy(packet_send.padding,&version,sizeof(version));
    memcpy(packet_send.padding + 32,&username,strlen(username));
    packet_send.eap_id = packet_recv.eap_id;
    return send(client_fd, &packet_send, 18 + ntohs(packet_send.x_length), 0);
}

int send_md5()
{
    packet_send.x_type = EAPOL_EAPPACKET;
    packet_send.x_length = htons(5 + 17 + strlen(username));
    packet_send.eap_code = EAP_RESPONSE;
    packet_send.eap_id = packet_recv.eap_id;
    packet_send.eap_type = EAP_TYPE_MD5;
    packet_send.eap_length = packet_send.x_length;
    packet_send.padding[0] = 0x10;

    md5buf[0] = packet_recv.eap_id;
    memcpy(md5buf+1, password, strlen(password));
    memcpy(md5buf+1+strlen(password), packet_recv.padding + 1, 16);
    MD5(md5buf, 17+strlen(password), packet_send.padding + 1);
    
    memcpy(packet_send.padding + 17,&username,strlen(username));
    return send(client_fd, &packet_send, 18 + ntohs(packet_send.x_length), 0);
}

int packet_handler()
{
    printf("Recv:%02X,%02X\n",packet_recv.eap_code,packet_recv.eap_type);
    if(packet_recv.x_type != EAPOL_EAPPACKET) return 1;
    switch (packet_recv.eap_code) {
        case EAP_REQUEST:
            switch(packet_recv.eap_type) {
                case EAP_TYPE_ID:
                    send_id();
                    break;
                case EAP_TYPE_MD5:
                    send_md5();
                    break;
            }
            break;
        case EAP_MESSAGE:
            break;
        case EAP_SUCCESS:
            fprintf(stdout,"Successed!\n");
            set_socket_timeout(15);
            system(dhcpscript);
            break;
        case EAP_FAILURE:
            return EAP_FAILURE;
    }
    return 0;
}

void auth_loop()
{
    int retry;
    retry = 1;
    send_start();
    set_socket_timeout(5);
    while(1) {
        if (recv(client_fd, &packet_recv, sizeof(packet_recv), 0) < 0) {
            if(retry--) {
                perror("Retry");
                send_id();
            }
            else {
                send_logoff();
                perror("Restart");
                return;
            }
        } else {
            retry = 1;
            memcpy(packet_send.dst_mac, packet_recv.src_mac, 6);
            if (packet_handler() == EAP_FAILURE) {
                return;
            };
        }
    }
}

void auth_close()
{
    struct ifreq ifr;
    send_logoff();
    memset(&ifr, 0 , sizeof(ifr));
    strncpy(ifr.ifr_name, ifname , sizeof(ifr.ifr_name));
    if (ioctl(client_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("Interface IO error");
    }
    ifr.ifr_flags = ifr.ifr_flags & (~IFF_PROMISC);
    if (ioctl(client_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Interface IO error");
    }
    close(client_fd);
}
