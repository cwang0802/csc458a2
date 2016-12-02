#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

uint16_t calc_ip_cksum(struct sr_ip_hdr *ip_header) {
  uint16_t newCksum;
  uint16_t currCksum; 

  currCksum = ip_header->ip_sum; 
  ip_header->ip_sum = 0;
  newCksum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  
  ip_header->ip_sum = currCksum; 

  return newCksum;
}

uint16_t calc_icmp_cksum(struct sr_icmp_hdr *icmp_header, int len) {
	uint16_t newCksum;
	uint16_t currCksum;

 	currCksum = icmp_header->icmp_sum;
	icmp_header->icmp_sum = 0;
	newCksum = cksum(icmp_header, len);
  	icmp_header->icmp_sum = currCksum;

	return newCksum;
}

uint16_t calc_tcp_cksum(struct sr_tcp_hdr *tcp_header, int len) {
  uint16_t newCksum;
  uint16_t currCksum;

  currCksum = tcp_header->tcp_sum;
  tcp_header->tcp_sum = 0;
  newCksum = cksum(tcp_header, len);
    tcp_header->tcp_sum = currCksum;

  return newCksum;
}

uint16_t calc_icmp3_cksum(struct sr_icmp_t3_hdr *icmp3_header) {
  uint16_t newCksum;
  uint16_t currCksum; 

  currCksum = icmp3_header->icmp_sum; 
  icmp3_header->icmp_sum = 0;
  newCksum = cksum(icmp3_header, sizeof(sr_icmp_t3_hdr_t));
  icmp3_header->icmp_sum = currCksum;

  return newCksum;
}

/*int validate_packet(struct sr_ip_hdr *ip_header, int len) {
  if (ip_header->ip_len > ip_header->ip_hl || cksum(ip_header, sizeof(sr_ip_hdr_t) == 0xffff || ip_header->ip_v != 4 || len < 20 || ip_header->ip_hl < 5)) {
    return 0;
  }

  return 1;
}*/

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/*
struct sr_tcp_hdr {
  uint16_t tcp_src;
  uint16_t tcp_dst;
  uint32_t tcp_seq;
  uint32_t tcp_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int tcp_data_off:4;   
    unsigned int tcp_reserved:3;  
    unsigned int tcp_flags:9;    
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int tcp_flags:9;    
    unsigned int tcp_reserved:3;   
    unsigned int tcp_data_off:4;  
#else
#error "Byte ordering not specified " 
#endif 
  uint16_t tcp_win;
  uint16_t tcp_sum;
  uint16_t tcp_urg;

*/
/* Prints out fields in TCP header. */
void print_hdr_tcp(uint8_t *buf) {
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *)(buf);
  fprintf(stderr, "TCP header:\n");
  fprintf(stderr, "\tsource port: %d\n", tcphdr->tcp_src);
  fprintf(stderr, "\tdest port: %d\n", tcphdr->tcp_dst);
  fprintf(stderr, "\tsequence: %d\n", tcphdr->tcp_seq);
  fprintf(stderr, "\tack number: %d\n", tcphdr->tcp_ack);
  fprintf(stderr, "\tdata offset: %d\n", tcphdr->tcp_data_off);
  fprintf(stderr, "\treserved: %d\n", tcphdr->tcp_reserved);
  fprintf(stderr, "\tflags: %d\n", tcphdr->tcp_flags);

  fprintf(stderr, "\twindow size: %d\n", tcphdr->tcp_win);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", tcphdr->tcp_sum);

  fprintf(stderr, "\turgent: %d\n", tcphdr->tcp_urg);
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

