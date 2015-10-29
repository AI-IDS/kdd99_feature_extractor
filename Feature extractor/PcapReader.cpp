
#include <iostream>
#include "PcapReader.h"
#include "net.h"
#include "Frame.h"
#include <assert.h>

// prevent localtime warning
#pragma warning(disable : 4996)

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
		assert(header->len >= eth->ETH2_HEADER_LENGTH + ip->IP_MIN_HEADER_LENGTH);
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
			assert(f->get_ip_payload_length() >= tcp->TCP_MIN_HEADER_LENGTH);
			f->set_src_port(ntohs(tcp->src_port));
			f->set_dst_port(ntohs(tcp->dst_port));
			f->set_tcp_flags(tcp->flags);
			break;

		case UDP:
			udp = (udp_header_t *)ip->get_sdu();
			assert(f->get_ip_payload_length() >= udp->UDP_MIN_HEADER_LENGTH);
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

	PcapReader::~PcapReader()
	{
	}
}

