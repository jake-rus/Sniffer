/*
 * sniffer_multi.c
 * Sniffing one packet with view Eth + IP + TCP Header's
 *  Created on: 26.03.2018
 *      Author: jake
 */

#include "add.h"

void packet_grab(u_char *arg, const struct pcap_pkthdr* header,
		const u_char* packet);

int main(int argc,char **argv)	// argv[1] выражение фильтра
{
	int i;
	char *dev,*net,*mask; 		// имя сетевого устройства, IP & MASK
	pcap_t* descr; 				// идентификатор устройства
	char errbuf[PCAP_ERRBUF_SIZE]; // строка для хранения ошибок
	bpf_u_int32 maskp;         //маска подсети
	bpf_u_int32 netp;          // ip
	struct bpf_program fp;     //выражение фильтрации в составленном виде
	struct in_addr addr;		// сетевой адрес интерфейса
	const u_char *packet;  		// Пакет/
	struct pcap_pkthdr header; // Заголовок который нам дает PCAP

	bzero(&fp,sizeof(fp));
	bzero(&addr,sizeof(addr));
	bzero(&header,sizeof(header));

	/* Получение имени устройства для захвата пакетов */
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	/* Получение сетевого адреса и маски сети для устройства */
	if (pcap_lookupnet(dev,&netp,&maskp,errbuf)==-1)
	{
		fprintf(stderr,"%s\n",errbuf);
	    exit(1);
	}
	/* Преобразование в человеческий вид */
	addr.s_addr = netp;
	if ((net = inet_ntoa(addr))==NULL)
	{
	    perror("inet_ntoa");
	    exit(1);
	}
	printf("DEV: %s\nNET: %s\n",dev,net);
	addr.s_addr = maskp;
	if ((mask = inet_ntoa(addr))==NULL)
		{
		    perror("inet_ntoa");
		    exit(1);
		}
	printf("MASK: %s\n",mask);

	/* открытие устройства в  promiscuous-режиме */
	descr = pcap_open_live(dev, BUFSIZ, 1,1000, errbuf);
	if(descr == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}

	/* теперь составляется выражение фильтрации*/
	if(pcap_compile(descr, &fp, argv[1], 0, maskp) == -1) {
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(1);
	}

	/* применение фильтра*/
	if(pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "Error setting filter\n");
		exit(1);
	}

	/* функция обратного вызова используется в цикле */
	pcap_loop(descr, -1, packet_grab, NULL);

	/* Закрытие сессии */
	pcap_close(descr);

	return 0;
}

