
#include <iostream>
#include "PcapReader.h"
#include "net.h"
#include "Frame.h"

namespace FeatureExtractor {
	
	using namespace std;

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

	IpFragment *PcapReader::next_frame()
	{
		struct pcap_pkthdr *header;
		const u_char *data;

		/* Retrieve the packet */
		if (pcap_next_ex(this->handle, &header, &data) != 1) {
			return NULL;
		}

		IpFragment *f = new IpFragment();
		f->set_start_ts(header->ts);
		f->set_length(header->len + ADDITIONAL_LEN);	// Additional lenght for e.g. CRC of Ethernet

		// Ethernet type/length field
		ether_header_t *eth = (ether_header_t *)data;
		if (!eth->is_ethernet2())
			return f;
		f->set_eth2(true);
		f->set_eth_type((eth_field_type_t)ntohs(eth->type_length));
		if (!eth->is_type_ipv4())
			return f;

		// IP
		ip_header_t *ip = (ip_header_t *)eth->get_eth2_sdu();
		f->set_src_ip(ip->src_addr);
		f->set_dst_ip(ip->dst_addr);
		f->set_ip_proto(ip->protocol);
		f->set_ip_id(ntohs(ip->id));
		f->set_ip_flag_mf(ip->flag_mf());
		f->set_ip_frag_offset(ip->frag_offset());
		f->set_ip_payload_length(ntohs(ip->total_length) - ip->header_length());

		// Look for L4 headers only in first fragment
		if (f->get_ip_frag_offset() > 0)
			return f;

		// L4 - TCP & UDP
		tcp_header_t *tcp = NULL;
		udp_header_t *udp = NULL;
		switch (ip->protocol) {
		case TCP:
			tcp = (tcp_header_t *)ip->get_sdu();
			f->set_src_port(ntohs(tcp->src_port));
			f->set_dst_port(ntohs(tcp->dst_port));
			f->set_tcp_flags(tcp->flags);
			break;

		case UDP:
			udp = (udp_header_t *)ip->get_sdu();
			f->set_src_port(ntohs(udp->src_port));
			f->set_dst_port(ntohs(udp->dst_port));
			break;

		case ICMP:
		default:
			// No special handling
			break;
		}

		return f;
	}





//#pragma warning(disable : 4996)
	int PcapReader::old_next_frame()
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

		// ---------- test output


		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		cout << timestr;

		{
			ether_header_t *eth_test = (ether_header_t *)data;
			//eth->type_length = (eth_field_type_t) ntohs(eth->type_length);
			if (eth_test->is_ethernet2())
			{
				cout << " Ethernet II";
			}
			else {
				cout << " NON-Ethernet Frame" << endl;
				return 1;
			}
			if (!eth_test->is_type_ipv4()) {
				cout << " >> NON-IP(0x" << hex << eth_test->type_length << dec << ")" << endl;
				return 1;
			}
			cout << " >> IP";

			// IP
			ip_header_t *ip_test = (ip_header_t *)eth_test->get_eth2_sdu();
			ip_test->total_length = ntohs(ip_test->total_length);
			cout << "(" << hex << (int)ip_test->flags() << dec << ", " << ip_test->frag_offset() << ")";
			cout << " >> " << ip_test->protocol_str() << endl;

			uint8_t *src_ip = (uint8_t *)&ip_test->src_addr;
			uint8_t *dst_ip = (uint8_t *)&ip_test->dst_addr;


			if (ip_test->protocol != TCP && ip_test->protocol != UDP) {
				cout << "  src=" << (int)src_ip[0] << "." << (int)src_ip[1] << "." << (int)src_ip[2] << "." << (int)src_ip[3];
				cout << " dst=" << (int)dst_ip[0] << "." << (int)dst_ip[1] << "." << (int)dst_ip[2] << "." << (int)dst_ip[3];
				cout << " length=" << ip_test->total_length << endl;  // ntoh applied
				return 1;
			}


			unsigned int sport = 0;
			unsigned int dport = 0;
			// TCP
			if (ip_test->protocol == TCP) {
				tcp_header_t *tcp = (tcp_header_t *)ip_test->get_sdu();
				sport = ntohs(tcp->src_port);
				dport = ntohs(tcp->dst_port);
			}

			// UDP
			if (ip_test->protocol == UDP) {
				udp_header_t *udp = (udp_header_t *)ip_test->get_sdu();
				sport = ntohs(udp->src_port);
				dport = ntohs(udp->dst_port);
			}

			cout << "  src=" << (int)src_ip[0] << "." << (int)src_ip[1] << "." << (int)src_ip[2] << "." << (int)src_ip[3] << ":" << sport;
			cout << " dst=" << (int)dst_ip[0] << "." << (int)dst_ip[1] << "." << (int)dst_ip[2] << "." << (int)dst_ip[3] << ":" << dport;
			cout << " length=" << ip_test->total_length << endl;  // ntoh applied

			return 1;

		}
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

