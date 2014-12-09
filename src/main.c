#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <getopt.h>
#include "auth.h"

static struct option arglist[] = {
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        {"password", required_argument, NULL, 'p'},
        {"script", optional_argument, NULL, 's'},
        {"iface", optional_argument, NULL, 'i'},
        {NULL, 0, NULL, 0}
};

static const char usage_str[] = "Usage:\n"
    "   -h --help           print this screen\n"
    "   -u --username       longin name\n"
    "   -p --password       password\n"
    "   -s --script         dhcp script\n"
    "   -i --iface          network interface (default eth0)\n";


void preexit(){
    auth_close(); 
    exit(EXIT_SUCCESS);

}


int main(int argc, char *argv[])
{
    char argval;

    if (geteuid() != 0) {
        fprintf(stderr, "You have to run the program as root\n");
        exit(EXIT_FAILURE);
    }

    while ((argval = getopt_long(argc, argv, "u:p:i:s:h", arglist, NULL)) != -1) {
        switch (argval) {
            case 'h':
                printf(usage_str);
                exit(EXIT_SUCCESS);
            case 'u':
                strncpy(username, optarg, sizeof(username));
                break;
            case 'p':
                strncpy(password, optarg, sizeof(password));
                break;
            case 'i':
                strncpy(ifname, optarg, sizeof(ifname));
                break;
            case 's':
                strncpy(dhcpscript, optarg, sizeof(dhcpscript));
                break;      
            default:
                exit(EXIT_FAILURE);
        }
    }

    if (strlen(username) == 0 || strlen(password) == 0) {
        printf(usage_str);
        exit(EXIT_SUCCESS);
    }

    if(signal(SIGINT,preexit) == SIG_ERR ||
            signal(SIGTERM,preexit) == SIG_ERR) {
        perror("signal error");
        exit(EXIT_FAILURE);
    }

    if (auth_init() < 0) return 0;

    while(1){
        auth_loop();
    }
    return 0;
}
