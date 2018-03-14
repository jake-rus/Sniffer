/*
 * packet_grab.c
 *
 *  Created on: 14 мар. 2018 г.
 *      Author: jake
 */

#include "add.h"

#define SIZE_ETHERNET 14

void packet_grab(u_char *arg, const struct pcap_pkthdr* header,
		const u_char* packet)
{
	int i;
	//	struct ether_header *eptr;  // net/ethernet.h
	const struct sniff_ethernet *ethernet; /* Заголовок Ethernet */
	const struct sniff_ip *ip; /* Заголовок IP */
	const struct sniff_tcp *tcp; /* Заголовок TCP */
	const char *payload; /* Данные пакета */
	u_int size_ip;
	u_int size_tcp;

	/* Заголовок Ethernet */
	struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Адрес назначения */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Адрес источника */
    u_short ether_type; /* IP? ARP? RARP? и т.д. */
	};

	/* Заголовок IP */
	struct sniff_ip {
    u_char ip_vhl;  /* версия << 4 | длина заголовка >> 2 */
    u_char ip_tos;  /* тип службы */
    u_short ip_len;  /* общая длина */
    u_short ip_id;  /* идентефикатор */
    u_short ip_off;  /* поле фрагмента смещения */
    #define IP_RF 0x8000  /* reserved флаг фрагмента */
    #define IP_DF 0x4000  /* dont флаг фрагмента */
    #define IP_MF 0x2000  /* more флаг фрагмента */
    #define IP_OFFMASK 0x1fff /* маска для битов фрагмента */
    u_char ip_ttl;  /* время жизни */
    u_char ip_p;  /* протокол */
    u_short ip_sum;  /* контрольная сумма */
    struct in_addr ip_src,ip_dst; /* адрес источника и адрес назначения */
	};
 #define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
 #define IP_V(ip)  (((ip)->ip_vhl) >> 4)

	/* Заголовок TCP */
	typedef u_int tcp_seq;

	struct sniff_tcp {
    u_short th_sport; /* порт источника */
    u_short th_dport; /* порт назначения */
    tcp_seq th_seq;  /* номер последовательности */
    tcp_seq th_ack;  /* номер подтверждения */
    u_char th_offx2; /* смещение данных, rsvd */
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;  /* окно */
    u_short th_sum;  /* контрольная сумма */
    u_short th_urp;  /* экстренный указатель */
	};

	// Выделение загловков
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		exit(1);
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
	    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	    exit(1);
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* Вывод длины пакета,даты и длины Eth-заголовка*/
	printf("Recieved Packet Size: %d\n", (int)header->len); /* Длина пакета */
	printf("Recieved at ..... %s",ctime((const time_t*)&header->ts.tv_sec));
	printf("Ethernet address length is %d bytes\n\n",ETHER_HDR_LEN);

	/* Вывод загoловка Ethernet*/
	i = 0;
	printf(" Destination Address:  ");
	do{
		printf("%02x%s",ethernet->ether_dhost[i],(i<ETHER_ADDR_LEN-1)?":":"");
	}while(++i<ETHER_ADDR_LEN);
	printf("\n");
	i = 0;
    printf(" Source Address:  ");
    do{
        printf("%02x%s",ethernet->ether_shost[i],(i<ETHER_ADDR_LEN-1)?":":"");
    }while(++i<ETHER_ADDR_LEN);
    printf("\n");
    if (ntohs (ethernet->ether_type) == ETHERTYPE_IP)
    {
 	printf("Ethernet type hex:%x dec:%d is an IP packet\n",
 			ntohs(ethernet->ether_type),
            ntohs(ethernet->ether_type));
    }else  if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
    {
 	printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
 			ntohs(ethernet->ether_type),
            ntohs(ethernet->ether_type));
    }else {
    printf("Ethernet type %x not IP", ntohs(ethernet->ether_type));
    exit(1);
    }

	/* Вывод данных пакета */
	printf("Payload:\n");
	for(i=0;i<header->len;i++) {
		//if(isprint(packet[i]))	/* Проверка, является ли символ печатаемым */
		//printf("%c ",packet[i]);	/* Печать символа в ASCII*/
		printf("%02x ",packet[i]);	/* Печать символа в HEX*/
		//else
		//printf(" . ",packet[i]);	/* Если символ непечатаемый, вывод . */
		if((i%16==0 && i!=0) || i==header->len-1)
		printf("\n");
	}
}
