#include <iostream>
#include "PcapReader.h"
#include "net.h"



using namespace std;

namespace FeatureExtractor {
	PcapReader::PcapReader(char *fname)
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		// Open the capture file
		if ((this->handle = pcap_open_offline(fname, errbuf)) == NULL)
		{
			cerr << "Error: Unable to open the file " << fname << endl;
			exit(-1);
		}

		// Limit snapshot length
		pcap_set_snaplen(this->handle, SNAPLEN);
	}

	PcapReader::PcapReader(int inum)
	{
		pcap_if_t *alldevs;
		pcap_if_t *d;
		char errbuf[PCAP_ERRBUF_SIZE];
		int i;

		// Retrieve the device list
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			cerr << "Error in pcap_findalldevs: " << errbuf << endl;
			exit(-1);
		}

		// Jump to the selected adapter
		for (d = alldevs, i = 1; d && i < inum; d = d->next, i++)
			;

		if (inum < 1 || inum > i)
		{
			cerr << "Interface number out of range." << endl;
			pcap_freealldevs(alldevs);
			exit(-1);
		}

		// Open the adapter in promiscuous mode, limit snaphot length
		if ((this->handle = pcap_open_live(d->name, SNAPLEN, 1, 2000, errbuf)) == NULL)
		{
			cerr << "Unable to open the adapter. " << d->name << " is not supported by WinPcap" << endl;
			pcap_freealldevs(alldevs);
			exit(-1);
		}

		cout << "Interface: " << d->name << endl << d->description << endl;
		pcap_freealldevs(alldevs);
	}

#pragma warning(disable : 4996)
	int PcapReader::next_frame()
	{
		struct pcap_pkthdr *header;
		const u_char *data;

		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;

		/* Retrieve the packet */
		if (pcap_next_ex(this->handle, &header, &data) != 1) {
			return 0;
		}

		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		cout << timestr;

		// ----------
		ether_header_t *eth = (ether_header_t *) data;
		eth->type_length = (eth_field_type) ntohs(eth->type_length);
		if (eth->is_ethernet2())
		{
			cout << " Ethernet II";
		}
		else {
			cout << " NON-Ethernet Frame" << endl;
			return 1;
		}
		if (!eth->is_type_ipv4()) {
			cout << " >> NON-IP(0x" << hex << eth->type_length << dec << ")" << endl;
			return 1;
		}
		cout << " >> IP";

		// IP
		ip_header_t *ip = (ip_header_t *)eth->get_eth2_sdu();
		ip->total_length = ntohs(ip->total_length);
		cout << "(" << hex << (int)ip->flags() << dec << ", " << ip->frag_offset() * 8 << ")";
		cout << " >> " << ip->protocol_str() << endl;

		uint8_t *src_ip = (uint8_t *)&ip->src_addr;
		uint8_t *dst_ip = (uint8_t *)&ip->dst_addr;


		if (ip->protocol != TCP && ip->protocol != UDP) {
			cout << "  src=" << (int)src_ip[0] << "." << (int)src_ip[1] << "." << (int)src_ip[2] << "." << (int)src_ip[3];
			cout << " dst=" << (int)dst_ip[0] << "." << (int)dst_ip[1] << "." << (int)dst_ip[2] << "." << (int)dst_ip[3];
			cout << " length=" << ip->total_length << endl;  // ntoh applied
			return 1;
		}


		unsigned int sport = 0;
		unsigned int dport = 0;
		// TCP
		if (ip->protocol == TCP) {
			tcp_header_t *tcp = (tcp_header_t *) ip->get_sdu();
			sport = ntohs(tcp->src_port);
			dport = ntohs(tcp->dst_port);
		}

		// UDP
		if (ip->protocol == UDP) {
			udp_header_t *udp = (udp_header_t *)ip->get_sdu();
			sport = ntohs(udp->src_port);
			dport = ntohs(udp->dst_port);
		}

		cout << "  src=" << (int)src_ip[0] << "." << (int)src_ip[1] << "." << (int)src_ip[2] << "." << (int)src_ip[3] << ":" << sport;
		cout << " dst=" << (int)dst_ip[0] << "." << (int)dst_ip[1] << "." << (int)dst_ip[2] << "." << (int)dst_ip[3] << ":" << dport;
		cout << " length=" << ip->total_length << endl;  // ntoh applied

		return 1;

		// -------------- old v 0.1


		// Type/Length
		int type_length = (data[12] << 8) + data[13];
		if (type_length >= 0x600)
		{
			cout << " Ethernet II";
		}
		else {
			cout << " NON-Ethernet Frame" << endl;
			return 1;
		}

		if (type_length != 0x800) {
			cout << " >> NON-IP(0x" << hex << type_length << dec << ")" << endl;
			return 1;
		}
		cout << " >> IP";

		// IP
		const u_char *ip_data = &data[14];
		int ip_src[] = { ip_data[12], ip_data[13], ip_data[14], ip_data[15] };
		int ip_dst[] = { ip_data[16], ip_data[17], ip_data[18], ip_data[19] };
		int ip_len = (ip_data[2] << 8) + ip_data[3];
		int ip_protocol = ip_data[9];
		int ip_header_len = (ip_data[13] >> 4) << 2;  // 4bits, multiply by 4

		if (ip_protocol != 6 && ip_protocol != 17) {
			if (ip_protocol == 1)
				cout << " >> ICMP" << endl;
			else
				cout << " >> other(" << ip_protocol << ")" << endl;

			cout << "  src=" << ip_src[0] << "." << ip_src[1] << "." << ip_src[2] << "." << ip_src[3];
			cout << " dst=" << ip_dst[0] << "." << ip_dst[1] << "." << ip_dst[2] << "." << ip_dst[3];
			cout << " length=" << ip_len << endl;
			return 1;
		}

		// TCP & UDP - ports same
		const u_char *trans_data = &ip_data[ip_header_len];
		unsigned int src_port = (trans_data[0] << 8 + trans_data[1]);
		unsigned int dst_port = (trans_data[0] << 8 + trans_data[1]);
		if (ip_protocol == 6) {
			cout << " >> TCP" << endl;
		}
		else {
			cout << " >> UDP" << endl;
		}

		cout << "  src=" << ip_src[0] << "." << ip_src[1] << "." << ip_src[2] << "." << ip_src[3] << ":" << src_port;
		cout << " dst=" << ip_dst[0] << "." << ip_dst[1] << "." << ip_dst[2] << "." << ip_dst[3] << ":" << dst_port;
		cout << " length=" << ip_len << endl;









		//Frame *frame = new Frame();


		return 1;
		//return frame;
	}


	PcapReader::~PcapReader()
	{
	}
}

