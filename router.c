#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ICMP_TIME_EXC 11
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO 8
#define ICMP_ECHO_REPLY 0

struct route_table_entry *getNextHop(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len)
{
    struct route_table_entry *nextHop = NULL;

    for (int i = 0; i < rtable_len; i++)
    {
        if ((ip_dest & rtable[i].mask) == rtable[i].prefix)
        {
            if (nextHop == NULL)
                nextHop = &rtable[i];
            else if (ntohl(nextHop->mask) < ntohl(rtable[i].mask))
            {
                nextHop = &rtable[i];
            }
        }
    }

    return nextHop;
}

struct arp_table_entry *getNextHopMAC(uint32_t ip_dest, struct arp_table_entry *ARPtable, int arptable_len)
{
    int i;
    for (i = 0; i < arptable_len; i++)
        if (ARPtable[i].ip == ip_dest)
            return &ARPtable[i];

    return NULL;
}

void sendICMP(int errcode, char *buf, int interface, struct ether_header *eth_hdr, struct iphdr *iphdr, size_t len)
{
    // identifying ICMP packet starting address
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    char *icmpBuffer;
    int ofst = 0;

    if (errcode == ICMP_ECHO_REPLY)
    {
        //get_interface_mac(interface, eth_hdr->ether_shost);

        //swapping the MAC addresses
        uint8_t auxMAC[6];
        memcpy(auxMAC, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
        memcpy(eth_hdr->ether_shost, auxMAC, sizeof(auxMAC));

        // decrementing ttl
        (iphdr->ttl)--;

        //swapping the IP addresses
        uint32_t auxIP = iphdr->saddr;
        iphdr->saddr = iphdr->daddr;
        iphdr->daddr = auxIP;

        iphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
        iphdr->check = 0;
        iphdr->check = htons(checksum((uint16_t*)(iphdr), sizeof(struct iphdr)));

        // modifying the ICMP header
        memset(icmp_hdr, 0, sizeof(struct icmphdr));
        icmp_hdr->type = ICMP_ECHO_REPLY;
        icmp_hdr->code = 0;
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(iphdr->tot_len) - sizeof(struct iphdr) + sizeof(struct icmphdr)));

        //sending the packet forward
        send_to_link(interface, buf, len);
    }
    else
    {
        // saving the original IP header
        struct iphdr *oldIPhdr = malloc(sizeof(struct iphdr));
        memcpy(oldIPhdr, iphdr, sizeof(struct iphdr));

        // modifying the Ethernet header
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
        get_interface_mac(interface, eth_hdr->ether_shost);
        eth_hdr->ether_type = ntohs(ETHERTYPE_IP);

        // modifying the IP header
        iphdr->protocol = IPPROTO_ICMP;
        iphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
        iphdr->ttl = 255;
        iphdr->check = 0;
        iphdr->check = checksum((uint16_t *)iphdr, sizeof(struct iphdr));

        // constructing the ICMP header
        memset(icmp_hdr, 0, sizeof(struct icmphdr));
        icmp_hdr->type = errcode;
        icmp_hdr->code = 0;
        icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

        // constructing the ICMP packet for time exceeded or destination unreachable
        icmpBuffer = malloc(sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
        ofst = 0;
        memcpy(icmpBuffer, buf, sizeof(struct ether_header));
        ofst += sizeof(struct ether_header);
        memcpy(icmpBuffer + ofst, buf + ofst, sizeof(struct iphdr));
        ofst += sizeof(struct iphdr);
        memcpy(icmpBuffer + ofst, icmp_hdr, sizeof(struct icmphdr));
        ofst += sizeof(struct icmphdr);
        memcpy(icmpBuffer + ofst, oldIPhdr, sizeof(struct iphdr));
        ofst += sizeof(struct iphdr);
        memcpy(icmpBuffer + ofst, buf + ofst - sizeof(struct iphdr), 8);
        ofst += 8;

        // sending the packet forward
        send_to_link(interface, icmpBuffer, ofst);
    }
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // initializing the routing table
    struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
    int rtable_len = read_rtable(argv[1], rtable);

    // initializing the ARP table
    struct arp_table_entry *ARPtable = malloc(10 * sizeof(struct arp_table_entry));
    int arptable_len = parse_arp_table("arp_table.txt", ARPtable);

    uint8_t broadcastMAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Do not modify this line
    init(argc - 2, argv + 2);

    while (1)
    {

        int interface;
        size_t len;

        // printf("packet received!!!\n");
        // fflush(NULL);

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        // packets ignored if too short
        if (sizeof(buf) < sizeof(struct ether_header) + sizeof(struct iphdr))
        {
            memset(buf, 0, sizeof(buf));
            continue;
        }

        // identifying ethernet header
        struct ether_header *eth_hdr = (struct ether_header *)buf;
        uint8_t hostMAC[6];
        get_interface_mac(interface, (uint8_t *)hostMAC);
        uint8_t etherDestMAC[6];
        memcpy(etherDestMAC, eth_hdr->ether_dhost, 6);
        uint16_t etherType = eth_hdr->ether_type;

        // checking if destination MAC is host MAC or broadcast
        if (memcmp(etherDestMAC, hostMAC, 6) != 0 && memcmp(etherDestMAC, broadcastMAC, 6) != 0)
        {
            memset(buf, 0, sizeof(buf));
            continue;
        }

        // ignoring packets that are not IPv4 or ARP
        if (etherType != ntohs(0x0800) && etherType != ntohs(0x0806))
        {
            memset(buf, 0, sizeof(buf));
            continue;
        }

        // IPv4 packet
        if (etherType == ntohs(0x0800))
        {
            // printf("ajunge aici\n");
            // identifying IP header
            struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
            uint32_t *hostIP = (uint32_t *)get_interface_ip(interface);
            uint32_t destIP = ntohs(ip_hdr->daddr);

            // checking header integrity using checksum
            uint16_t oldChecksum = ip_hdr->check;
            ip_hdr->check = 0;
            if (oldChecksum != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))))
            {
                memset(buf, 0, sizeof(buf));
                continue;
            }

            // checking if TTL expired
            if (ip_hdr->ttl <= 1)
            {
                sendICMP(ICMP_TIME_EXC, buf, interface, eth_hdr, ip_hdr, len);
                memset(buf, 0, sizeof(buf));
                continue;
            }

            // ICMP echo
            if (ip_hdr->protocol == IPPROTO_ICMP) {
                struct icmphdr* icmphdr = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
                if (icmphdr->type == ICMP_ECHO && icmphdr->code == 0)
                {
                    sendICMP(ICMP_ECHO_REPLY, buf, interface, eth_hdr, ip_hdr, len);
                    memset(buf, 0, sizeof(buf));
                    continue;
                }
            }

            // decrementing TTL
            uint16_t oldTTL;
            oldTTL = ip_hdr->ttl;
            (ip_hdr->ttl)--;

            // getting IP address of next hop
            struct route_table_entry *nextHop = getNextHop(ip_hdr->daddr, rtable, rtable_len);
            if (nextHop == NULL)
            {
                sendICMP(ICMP_DEST_UNREACH, buf, interface, eth_hdr, ip_hdr, len);
                memset(buf, 0, sizeof(buf));
                continue;
                // send ICMP message (destination unreachable)
            }

            // updating checksum
            ip_hdr->check = ~(~oldChecksum + ~((uint16_t)oldTTL) + (uint16_t)ip_hdr->ttl) - 1;

            // rewriting the ethernet header
            // memcpy(eth_hdr->ether_shost, hostMAC, 6);
            memcpy(eth_hdr->ether_dhost, getNextHopMAC(nextHop->next_hop, ARPtable, arptable_len)->mac, sizeof(eth_hdr->ether_dhost));
            eth_hdr->ether_type = ntohs(0x0800);

            get_interface_mac(nextHop->interface, eth_hdr->ether_shost);

            // sending the packet forward
            send_to_link(nextHop->interface, buf, len);
        }

        // ARP packet
        if (etherType == ntohs(0x0806))
        {
            memset(buf, 0, sizeof(buf));
            continue;
        }

        /* Note that packets received are in network order,
        any header field which has more than 1 byte will need to be conerted to
        host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
        sending a packet on the link, */
    }
}
