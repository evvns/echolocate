#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define MAX_PORT 65535

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("[ECHOLOCATE] Usage: %s <hostname or IP address>\n", argv[0]);
        return 1;
    }

    char *target = argv[1];

    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(target)) == NULL) {
        printf("Error: Could not resolve host.\n");
        return 1;
    }

    printf("Scanning ports on %s...\n", host->h_name);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        printf("Error: Could not create socket.\n");
        return 1;
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        printf("Error: Could not set socket option.\n");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

    char packet[4096];
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_hdr->id = htonl(54321);
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 255;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->check = 0;
    ip_hdr->saddr = inet_addr("192.168.1.100");
    ip_hdr->daddr = addr.sin_addr.s_addr;

    tcp_hdr->source = htons(12345);
    tcp_hdr->dest = htons(80);
    tcp_hdr->seq = htonl(0);
    tcp_hdr->ack_seq = 0;
    tcp_hdr->doff = sizeof(struct tcphdr) / 4;
    tcp_hdr->syn = 1;
    tcp_hdr->window = htons(65535);
    tcp_hdr->check = 0;
    tcp_hdr->urg_ptr = 0;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr.sin_addr.s_addr;
    sin.sin_port = htons(80);

    int count = 0;
    FILE *fp = fopen("output.txt", "w");

    for (int port = 1; port <= MAX_PORT; port++) {
        tcp_hdr->dest = htons(port);
        tcp_hdr->check = 0;

        ip_hdr->check = 0;
        ip_hdr->check = htons(htons(in_cksum((unsigned short *)ip_hdr, sizeof(struct iphdr))) - (ip_hdr->check == 0));
        tcp_hdr->check = htons(htons(in_cksum((unsigned short *)tcp_hdr, sizeof(struct tcphdr) + sizeof(char))) - (tcp_hdr->check == 0));

        if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(char), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            printf("Error: Could not send packet.\n");
            return 1;
        }

        usleep(1000);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        if (select(sock + 1, &fds, NULL, NULL, &timeout) > 0) {
            int len = sizeof(sin);
            getsockname(sock, (struct sockaddr *)&sin, &len);

            char *ip = inet_ntoa(sin.sin_addr);
            char *hostname = host->h_name;

            fprintf(fp, "%s:%d\n", ip, port);

            printf("Port %d is open on %s (%s).\n", port, hostname, ip);

            count++;
        }
    }

    fclose(fp);
    close(sock);

    printf("echolocation complete: %d open ports found.\n", count);
    return 0;
}

unsigned short in_cksum(unsigned short *ptr, int nbytes) {
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}
