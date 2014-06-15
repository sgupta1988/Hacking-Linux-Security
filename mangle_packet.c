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
	char protocol;
	int counter;
};

struct ip_hdr_prof match_dest_hdr,match_src_hdr;
struct ip_hdr_prof change_dest_hdr,change_src_hdr;
struct ip_hdr_prof pkt_dest_hdr,pkt_src_hdr;
int hdr_list_count=0;

u_int16_t port_num;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
 
	u_int32_t queue_id;
	struct ip_hdr_prof pkt_dest_hdr,pkt_src_hdr;
	struct nfqnl_msg_packet_hdr *ph;
	int pkt_len;
	int i,verdict;
	u_int16_t *p_port;
	u_int16_t port_s,port_d;
	unsigned char *buf;
	size_t hdr_len;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		queue_id = ntohl(ph->packet_id);
	} else {
		return -1;
	}*/
	/* try to get at the actual packet */
	pkt_len = nfq_get_payload(nfa, &buf);

	//Packet source ip
	pkt_src_hdr.ip_addr[0]=*(char *)(buf+12);
	pkt_src_hdr.ip_addr[1]=*(char *)(buf+13);
	pkt_src_hdr.ip_addr[2]=*(char *)(buf+14);
	pkt_src_hdr.ip_addr[3]=*(char *)(buf+15);

	pkt_dest_hdr.ip_addr[0]=*(char *)(buf+16);
	pkt_dest_hdr.ip_addr[1]=*(char *)(buf+17);
	pkt_dest_hdr.ip_addr[2]=*(char *)(buf+18);
	pkt_dest_hdr.ip_addr[3]=*(char *)(buf+19);

	p_port=(u_int16_t *)(buf+20);
	port_s=ntohs(*p_port);
	p_port=(u_int16_t *)(buf+22);
	port_d=ntohs(*p_port);

	pkt_src_hdr.port_num=port_s;
	pkt_dest_hdr.port_num=port_d;

	pkt_src_hdr.protocol=*(char *)(buf+9);
	pkt_dest_hdr.protocol=*(char *)(buf+9);

	printf("\n\tSource IP= [%u.%u.%u.%u]\n\tsource_port=[%d]\n\tsource_protocol=[%d]",pkt_src_hdr.ip_addr[0],pkt_src_hdr.ip_addr[1],pkt_src_hdr.ip_addr[2],pkt_src_hdr.ip_addr[3],pkt_src_hdr.port_num,pkt_src_hdr.protocol);
	printf("\n\tDestination IP= [%u.%u.%u.%u]\n\tdestination_port=[%d]\n\tdestination_protocol=[%d]",pkt_dest_hdr.ip_addr[0],pkt_dest_hdr.ip_addr[1],pkt_dest_hdr.ip_addr[2],pkt_dest_hdr.ip_addr[3],pkt_dest_hdr.port_num,pkt_dest_hdr.protocol);
	// Match Packets to Change It
	if(
			(pkt_src_hdr.ip_addr[0]==match_src_hdr.ip_addr[0]) &&
			(pkt_src_hdr.ip_addr[1]==match_src_hdr.ip_addr[1]) &&
			(pkt_src_hdr.ip_addr[2]==match_src_hdr.ip_addr[2]) &&
			(pkt_src_hdr.ip_addr[3]==match_src_hdr.ip_addr[3]) &&
			(pkt_dest_hdr.ip_addr[0]==match_dest_hdr.ip_addr[0]) &&
			(pkt_dest_hdr.ip_addr[1]==match_dest_hdr.ip_addr[1]) &&
			(pkt_dest_hdr.ip_addr[2]==match_dest_hdr.ip_addr[2]) &&
			(pkt_dest_hdr.ip_addr[3]==match_dest_hdr.ip_addr[3]) 
	  )
	{
		printf("\n Matched ::  Changing Packet According to Provided Details \n");
		*(char *)(buf+12)=change_src_hdr.ip_addr[0];
		*(char *)(buf+13)=change_src_hdr.ip_addr[1];
		*(char *)(buf+14)=change_src_hdr.ip_addr[2];
		*(char *)(buf+15)=change_src_hdr.ip_addr[3];

		*(char *)(buf+16)=change_dest_hdr.ip_addr[0];
		*(char *)(buf+17)=change_dest_hdr.ip_addr[1];
		*(char *)(buf+18)=change_dest_hdr.ip_addr[2];
		*(char *)(buf+19)=change_dest_hdr.ip_addr[3];

		p_port=(u_int16_t *)(buf+20);
		*p_port=htons(change_src_hdr.port_num);

		p_port=(u_int16_t *)(buf+22);
		*p_port=htons(change_dest_hdr.port_num);

		*(char *)(buf+9)=change_src_hdr.protocol;



		pkt_src_hdr.ip_addr[0]=*(char *)(buf+12);
		pkt_src_hdr.ip_addr[1]=*(char *)(buf+13);
		pkt_src_hdr.ip_addr[2]=*(char *)(buf+14);
		pkt_src_hdr.ip_addr[3]=*(char *)(buf+15);

		pkt_dest_hdr.ip_addr[0]=*(char *)(buf+16);
		pkt_dest_hdr.ip_addr[1]=*(char *)(buf+17);
		pkt_dest_hdr.ip_addr[2]=*(char *)(buf+18);
		pkt_dest_hdr.ip_addr[3]=*(char *)(buf+19);

		p_port=(u_int16_t *)(buf+20);
		port_s=ntohs(*p_port);
		p_port=(u_int16_t *)(buf+22);
		port_d=ntohs(*p_port);

		pkt_src_hdr.port_num=port_s;
		pkt_dest_hdr.port_num=port_d;

		pkt_src_hdr.protocol=*(char *)(buf+9);
		pkt_dest_hdr.protocol=*(char *)(buf+9);

		printf("\n Changed Packet");
		printf("\n\tSource IP= [%u.%u.%u.%u]\n\tsource_port=[%d]\n\tsource_protocol=[%d]",pkt_src_hdr.ip_addr[0],pkt_src_hdr.ip_addr[1],pkt_src_hdr.ip_addr[2],pkt_src_hdr.ip_addr[3],pkt_src_hdr.port_num,pkt_src_hdr.protocol);
		printf("\n\tDestination IP= [%u.%u.%u.%u]\n\tdestination_port=[%d]\n\tdestination_protocol=[%d]",pkt_dest_hdr.ip_addr[0],pkt_dest_hdr.ip_addr[1],pkt_dest_hdr.ip_addr[2],pkt_dest_hdr.ip_addr[3],pkt_dest_hdr.port_num,pkt_dest_hdr.protocol);

		i=10000000;
		while(i-->0);
	}

	new_buf = malloc(pkt_len);
	if(new_buf==NULL){
		printf("\n malloc returned NULL \n");
		verdict = nfq_set_verdict(qh, queue_id, NF_ACCEPT, pkt_len, buf);
	}
	else{
		memcpy(new_buf, buf, pkt_len);
		verdict = nfq_set_verdict(qh, queue_id, NF_ACCEPT, pkt_len, new_buf);
	}
	return verdict;
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;

	char buf[4096] __attribute__ ((aligned));

	/***********************************************************************************/

	printf("\n Statistics for Matching Packet :\n");

	printf("\n\t Enter Source IP by dot seperation :");
	scanf("%d.%d.%d.%d",(int *)&(match_src_hdr.ip_addr[0]),(int*)&(match_src_hdr.ip_addr[1]),(int *)&(match_src_hdr.ip_addr[2]),(int *)&(match_src_hdr.ip_addr[3]));

	printf("\n\t Enter Source port :");
	scanf("%d",(int *)&(match_src_hdr.port_num));

	printf("\n\t Enter Destination IP by dot seperation :");
	scanf("%d.%d.%d.%d",(int *)&(match_dest_hdr.ip_addr[0]),(int*)&(match_dest_hdr.ip_addr[1]),(int *)&(match_dest_hdr.ip_addr[2]),(int *)&(match_dest_hdr.ip_addr[3]));

	printf("\n\t Enter Destination port :");
	scanf("%d",(int *)&(match_dest_hdr.port_num));

	printf("\n\t Enter Protocol used [ICMP=1],[TCP=6],[UDP=17] :");
	scanf("%d",(int *)&(match_dest_hdr.protocol));
	match_src_hdr.protocol=match_dest_hdr.protocol;


	printf("\n You Entered ::\n");
	printf("\n\tSource IP= [%u.%u.%u.%u]\n\tsource_port=[%d]\n\tsource_protocol=[%d]",match_src_hdr.ip_addr[0],match_src_hdr.ip_addr[1],match_src_hdr.ip_addr[2],match_src_hdr.ip_addr[3],match_src_hdr.port_num,match_src_hdr.protocol);

	printf("\n\tDestination IP= [%u.%u.%u.%u]\n\tdestination_port=[%d]\n\tdestination_protocol=[%d]",match_dest_hdr.ip_addr[0],match_dest_hdr.ip_addr[1],match_dest_hdr.ip_addr[2],match_dest_hdr.ip_addr[3],match_dest_hdr.port_num,match_dest_hdr.protocol);



	printf("\n Statistics for Changed Packet :\n");
	printf("\n\t Enter Source IP by dot seperation :");
	scanf("%d.%d.%d.%d",(int *)&(change_src_hdr.ip_addr[0]),(int*)&(change_src_hdr.ip_addr[1]),(int *)&(change_src_hdr.ip_addr[2]),(int *)&(change_src_hdr.ip_addr[3]));
	printf("\n\t Enter Source port :");
	scanf("%d",(int *)&(change_src_hdr.port_num));
	printf("\n\t Enter Destination IP by dot seperation :");
	scanf("%d.%d.%d.%d",(int *)&(change_dest_hdr.ip_addr[0]),(int*)&(change_dest_hdr.ip_addr[1]),(int *)&(change_dest_hdr.ip_addr[2]),(int *)&(change_dest_hdr.ip_addr[3]));
	printf("\n\t Enter Destination port :");
	scanf("%d",(int *)&(change_dest_hdr.port_num));
	printf("\n\t Enter Protocol used [ICMP=1],[TCP=6],[UDP=17] :");
	scanf("%d",(int *)&(change_dest_hdr.protocol));
	change_src_hdr.protocol=change_dest_hdr.protocol;

	printf("\n You Entered ::\n");
	printf("\n\tSource IP= [%u.%u.%u.%u]\n\tsource_port=[%d]\n\tsource_protocol=[%d]",change_src_hdr.ip_addr[0],change_src_hdr.ip_addr[1],change_src_hdr.ip_addr[2],change_src_hdr.ip_addr[3],change_src_hdr.port_num,change_src_hdr.protocol);

	printf("\n\tDestination IP= [%u.%u.%u.%u]\n\tdestination_port=[%d]\n\tdestination_protocol=[%d]",change_dest_hdr.ip_addr[0],change_dest_hdr.ip_addr[1],change_dest_hdr.ip_addr[2],change_dest_hdr.ip_addr[3],change_dest_hdr.port_num,change_dest_hdr.protocol);

	/*****************************************************************************************/
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

	while ((rv = recv(fd, buf2, sizeof(buf2), 0)) && rv >= 0) {
		//	printf("Received Packet Details\n");
		nfq_handle_packet(h, buf2, rv);
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
