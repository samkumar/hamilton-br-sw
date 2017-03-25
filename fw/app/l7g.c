
#include <stdio.h>
#include <inttypes.h>

#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"
#include "net/gnrc/netif/hdr.h"
#include <checksum/fletcher16.h>
#include <rethos.h>
#include <board.h>

#define CHANNEL_TAP 2

extern ethos_t ethos;

#define Q_SZ 256

// Prefix is 2001:470:4889:115/64
const uint8_t ipv6_prefix[] = { 0x20, 0x01, 0x04, 0x70, 0x48, 0x89, 0x01, 0x15 };

void _handle_incoming_pkt(gnrc_pktsnip_t *p)
{
    if (p->type != GNRC_NETTYPE_IPV6) {
        return;
    }

    /* Packet must be big enough to contain an IP header. */
    if (p->size < sizeof(ipv6_hdr_t)) {
        return;
    }

    /* Check IP address. */
    ipv6_hdr_t* iphdr = p->data;

    if (memcmp(&iphdr->dst, ipv6_prefix, sizeof(ipv6_prefix)) == 0) {
        /* TODO: actually send this packet on the 802.15.4 link. */
        return;
    }

    rethos_send_frame(&ethos, p->data, p->size, CHANNEL_TAP, RETHOS_FRAME_TYPE_DATA);
}

void* br_main(void *a)
{
    //printf("main l7g started");
    static msg_t _msg_q[Q_SZ];
    msg_t msg, reply;
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
    reply.content.value = -ENOTSUP;
    msg_init_queue(_msg_q, Q_SZ);
    gnrc_pktsnip_t* pkt = NULL;
    kernel_pid_t me_pid = thread_getpid();
    gnrc_netreg_entry_t me_reg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, me_pid);
    gnrc_netreg_register(GNRC_NETTYPE_IPV6 , &me_reg);
    while (1) {
        msg_receive(&msg);
        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                pkt = msg.content.ptr;
                _handle_incoming_pkt(pkt);
                gnrc_pktbuf_release(pkt);
                break;
             case GNRC_NETAPI_MSG_TYPE_SET:
             case GNRC_NETAPI_MSG_TYPE_GET:
                msg_reply(&msg, &reply);
                break;
            default:
                break;
        }

    }
}
static kernel_pid_t br_pid = 0;
static char br_stack[1024];
kernel_pid_t start_br(void)
{
  if (br_pid != 0)
  {
    return br_pid;
  }
  br_pid = thread_create(br_stack, sizeof(br_stack),
                          THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST,
                          br_main, NULL, "br");
  return br_pid;
}
