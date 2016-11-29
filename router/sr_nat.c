
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
  
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->last_updated = time(NULL);
  
  /* Loop through NAT until you find empty router*/
  
  struct sr_nat_mapping *lastMap = nat->mappings;
  
  while (lastMap->next) {
  lastMap = lastMap->next;
  }
  lastMap->next = mapping;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

void sr_handle_nat(
	struct sr_instance* sr, 
	uint8_t * packet, 
	unsigned int len, 
	char *iface,
  struct sr_ip_hdr *ip_header)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(len);
  
  
  /*Must check if its ICMP vs ARP*/
  printf("Ok, we are about to send a packet, must NATify it first! Here is what is inside the packet:\n");

  print_hdrs(packet, len);
  
  /* 
  check if ICMP or TCP
  if packet is outgoing (internal -> external):
    lookup unique mapping, and insert if not already in mapping table
  else:
    if no mapping and not a SYN:
      drop packet

  rewrite IP src for outgoing packets, rewrite IP dst for incoming packets
  rewrite ICMP id / TCP port #
  update checksums
  route packet as normal
  */   

  uint8_t protocol = ip_protocol((packet + sizeof(sr_ethernet_hdr_t)));

  struct sr_if *dest_if = sr_get_interface_by_ip(sr, ip_header->ip_dst);

  struct sr_rt *lpm_result = NULL;

  if (dest_if == 0) {
    lpm_result = sr_get_lpm_entry(sr->routing_table, ip_header->ip_dst);
  }

  /** UNTESTED CODE **/
  switch(protocol) {
    case ip_protocol_icmp:
      if (interface == 'eth1') {
        /* arrived on internal interface */
        if (lpm_result != NULL && lpm_result->interface != 'eth1') {
          /* going to external interface */

          sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          struct sr_nat_mapping *mapping_result = sr_nat_lookup_internal(&(sr->nat), ip_header->ip_src, icmp_header->icmp_id, nat_mapping_icmp);

          if (mapping_result == NULL) {
            mapping_result = sr_nat_insert_mapping(&(sr->nat), ip_header->ip_src, icmp_header->icmp_id, nat_mapping, icmp);
            mapping_result->ip_ext = sr_get_interface(sr, lpm_result->interface)->ip;
            uint16_t temp_aux_ext = get_new_icmp_id(&(sr->nat));
            if (temp_aux_ext != -1) {
              mapping_result->aux_ext = temp_aux_ext;
            } else {
              printf("No more ICMP IDs??? \n\n");
            }
          }

          ip_header->ip_src = mapping_result->ip_ext;
          icmp_header->icmp_id = mapping_result->aux_ext;
          ip_header->ip_sum = calc_ip_cksum(ip_header);
          icmp_header->icmp_sum = calc_icmp_cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        }

        sr_handle_regular_IP(sr, packet, len, interface, ip_header);
      } else {
        /* arrived on external interface */
        if (dest_if != 0) {
          /* going to internal interface */

          sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          struct sr_nat_mapping *mapping_result = sr_nat_lookup_external(&(sr->nat), icmp_header->icmp_id, nat_mapping_icmp);

          if (mapping_result != NULL) {

            /* NOTE: icmp type?? not sure yet... */
            ip_header->ip_dst = mapping_result->ip_int;
            icmp_header->icmp_id = mapping_result->aux_int;
            ip_header->ip_sum = calc_ip_cksum(ip_header);
            icmp_header->icmp_sum = calc_icmp_cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

            sr_handle_regular_IP(sr, packet, len, interface, ip_header);
          }
        } else {
          if (lpm_result->interface != 'eth1') {
            sr_handle_regular_IP(sr, packet, len, interface, ip_header);
          }
        }

      }

      break;

    case ip_protocol_tcp:
      break;

    default:
      break;
  }

}

uint16_t get_new_icmp_id(struct sr_nat *nat) {
  pthread_mutex_lock(&(nat->lock));

  uint16_t *icmp_ids = nat->icmp_ids;

  int i;
  int new_id = -1;
  for (i = 1; i <= MAX_IDS_PORTS - 1; i++) {
    if (icmp_ids[i] == 0) {
      icmp_ids[i] = 1;

      new_id = i;
      break;
    }
  }

  pthread_mutex_unlock(&(nat->lock));

  return new_id;
}