#ifndef _GDUTH3C_AUTH_H
#define _GDUTH3C_AUTH_H


#define AUTH_ERR -1

#define ETH_TYPE_PAE    0x888E

#define EAPOL_VERSION   1

/* EAPOL Type */
#define EAPOL_EAPPACKET 0
#define EAPOL_START     1
#define EAPOL_LOGOFF    2

/* EAP Code */
#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4
#define EAP_MESSAGE     10

/* EAP Type */
#define EAP_TYPE_ID     1
#define EAP_TYPE_MD5    4

struct packet {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short proto;
    unsigned char x_version;
    unsigned char x_type;
    unsigned short x_length;
    unsigned char eap_code;
    unsigned char eap_id;
    unsigned short eap_length;
    unsigned char eap_type;
    unsigned char padding[233];
};

inline int send_start_logoff(int type);
int auth_init(void);
int send_start(void);
int send_logoff(void);
int send_id(void);
int send_md5(void);
int packet_handler(void);
void auth_loop(void);
void auth_close(void);

extern char ifname[16];
extern char username[16];
extern char password[16];
extern char dhcpscript[32];

#endif /* _GDUTH3C_AUTH_H */
