#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <arpa/inet.h>
#include <time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

struct ip_hdr_prof{
	char ip_addr[4];
	u_int16_t port_num;
	int counter;
};

struct ip_hdr_prof hdr_list[4],*ip_hdr_ptr;
int hdr_list_count=0;

u_int16_t port_num;

/* Standard IPv4 header checksum calculation, as per RFC 791 */

u_int16_t ipv4_header_checksum(char *hdr, size_t hdrlen) {

  unsigned long sum = 0;
  const u_int16_t *bbp;
  int count = 0;

  bbp = (u_int16_t *)hdr;
  while (hdrlen > 1) {
    /* the checksum field itself should be considered to be 0 (ie, excluded) when calculating the checksum */
    if (count != 10) {
      sum += *bbp;
    } 
    bbp++; hdrlen -= 2; count += 2;
  }

  /* in case hdrlen was an odd number, there will be one byte left to sum */
  if (hdrlen > 0) {
    sum += *(unsigned char *)bbp;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return (~sum);
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	char p1,p2,p3,p4;
	int i =0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
        u_int16_t *p_port;
        u_int16_t port_s,port_d;
	u_int32_t source_ip,dest_ip,*ip_p; 

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("HW Protocol:0x%04x\tHOOK:%u\tPacket ID:%u\t",
				ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("Source Mac Address:");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x\t", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("Mark:%u\t", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("Indev:%u\t", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("Outdev:%u\t", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("Physindev:%u\t", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("Physoutdev:%u\t", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("Payload Length:%d", ret);
        i=0;
	printf("\n");

	/* try to get at the actual packet */
        p1=*(char *)(data+12);
        p2=*(char *)(data+13);
        p3=*(char *)(data+14);
        p4=*(char *)(data+15);
        ip_p=(u_int32_t *)(data+12);
	source_ip=(*ip_p); 
        printf("Source IP:%u.%u.%u.%u\t",p1,p2,p3,p4);

        p_port=(u_int16_t *)(data+20);
        port_s=ntohs(*p_port);
        printf("Source Port:%d\t",port_s);

        p1=*(char *)(data+16);
        p2=*(char *)(data+17);
        p3=*(char *)(data+18);
        p4=*(char *)(data+19);
        ip_p=(u_int32_t *)(data+16);
	dest_ip=(*ip_p); 
        printf("Dest IP:%u.%u.%u.%u\t",p1,p2,p3,p4);

        p_port=(u_int16_t *)(data+22);
        port_d=ntohs(*p_port);
        printf("Dest Port:%d\t",port_d);

        p1=*(char *)(data+9);
        printf("Protocol ID:%d\n",p1);

	if(port_num == port_s)
	{
		printf("Packet Matched Application Source Port\n");
	}
	else if(port_num==port_d)
	{
		printf("Packet Matched Application Dest Port\n");
	}
/***************************************************************/
        i=10000000;
        while(i-->0);
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
       
	char buf[4096] __attribute__ ((aligned));

        port_num=0;
        printf("Enter Source/Dest Port Number of your Application:");
        scanf("%d",&port_num);
        printf("\n");

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		printf("Received Packet Details\n");
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}


