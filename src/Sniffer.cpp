
#include <iostream>
#include <cstdlib>
#include "Sniffer.h"
#include "net.h"
#include <assert.h>

// Unknown netmask constant for filter creation
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

namespace FeatureExtractor {
	using namespace std;

	// Snapshot length (in bytes) - limited to improve performace
	// 96B = 14B Eth2 header + 60B max IP header length + 20 TCP basic header
	// This must be enlarged ("unlimited"), if deep packet inspection 
	// (i.e. payload analysis) is employed.
	const size_t Sniffer::SNAPLEN = 94;

	// We are interested only in this
	const char *Sniffer::DEFAULT_FILTER = "ip and (tcp or udp or icmp)";

	Sniffer::Sniffer(const char *fname, const Config *config)
		: additional_frame_length(config->get_additional_frame_len())
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		// Open the capture file
		if ((this->handle = pcap_open_offline(fname, errbuf)) == NULL)
		{
			cerr << "Error: Unable to open the file " << fname << endl;
			exit(1);
		}

		// Limit snapshot length
		pcap_set_snaplen(this->handle, SNAPLEN);

		// Filter unneeded network sh*t
		set_filter(DEFAULT_FILTER);
	}


	Sniffer::Sniffer(int inum, const Config *config)
		: additional_frame_length(config->get_additional_frame_len())
	{
		pcap_if_t *alldevs;
		pcap_if_t *d;
		char errbuf[PCAP_ERRBUF_SIZE];
		int i;

		// Retrieve the device list
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			cerr << "Error in pcap_findalldevs: " << errbuf << endl;
			exit(1);
		}

		// Jump to the selected adapter
		for (d = alldevs, i = 1; d && i < inum; d = d->next, i++)
			;

		if (inum < 1 || inum > i)
		{
			cerr << "Interface number out of range." << endl;
			pcap_freealldevs(alldevs);
			exit(1);
		}

		// Open the adapter in promiscuous mode, limit snaphot length
		int read_timeout = config->get_pcap_read_timeout();
		if ((this->handle = pcap_open_live(d->name, SNAPLEN, 1, read_timeout, errbuf)) == NULL)
		{
			cerr << "Unable to open the adapter. " << d->name << errbuf << endl;
			pcap_freealldevs(alldevs);
			exit(1);
		}

		pcap_freealldevs(alldevs);

		// Filter unneeded network sh*t
		set_filter(DEFAULT_FILTER);
	}


	void Sniffer::set_filter(const char *filter)
	{
		struct bpf_program filter_program;

		// Compile filter
		if (pcap_compile(handle, &filter_program, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
		{
			cerr <<  "Error compiling filter '" << filter << "'" << endl;
			exit(1);
		}

		// Set filter
		if (pcap_setfilter(handle, &filter_program) == -1)
		{
			cerr << "Error setting filter '" << filter << "'" << endl;
			exit(1);
		}
	}

	IpFragment *Sniffer::next_frame()
	{
		struct pcap_pkthdr *header;
		const u_char *data;

		/* Retrieve the packet */
		if (pcap_next_ex(this->handle, &header, &data) != 1) {
			return NULL;
		}

		IpFragment *f = new IpFragment();
		Timestamp ts(header->ts);
		f->set_start_ts(ts);
		f->set_length(header->len + additional_frame_length);	// Additional lenght for e.g. CRC of Ethernet

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
		assert(header->len >= eth->ETH2_HEADER_LENGTH + ip->IP_MIN_HEADER_LENGTH && "Packet too short to fit Ethernet header");
		f->set_src_ip(ip->src_addr);
		f->set_dst_ip(ip->dst_addr);
		f->set_ip_proto(ip->protocol);
		f->set_ip_id(ntohs(ip->id));
		f->set_ip_flag_mf(ip->flag_mf());
		f->set_ip_frag_offset((uint16_t) ip->frag_offset());
		f->set_ip_payload_length(ntohs(ip->total_length) - ip->header_length());

		// Look for L4 headers only in first fragment
		if (f->get_ip_frag_offset() > 0)
			return f;

		// L4 - TCP & UDP
		tcp_header_t *tcp = nullptr;
		udp_header_t *udp = nullptr;
		icmp_header_t *icmp = nullptr;
		switch (ip->protocol) {
		case TCP:
			assert(f->get_ip_payload_length() >= tcp->TCP_MIN_HEADER_LENGTH && "Packet too short to fit TCP header");
			tcp = (tcp_header_t *)ip->get_sdu();
			f->set_src_port(ntohs(tcp->src_port));
			f->set_dst_port(ntohs(tcp->dst_port));
			f->set_tcp_flags(tcp->flags);
			break;

		case UDP:
			assert(f->get_ip_payload_length() >= udp->UDP_MIN_HEADER_LENGTH && "Packet too short to fit UDP header");
			udp = (udp_header_t *)ip->get_sdu();
			f->set_src_port(ntohs(udp->src_port));
			f->set_dst_port(ntohs(udp->dst_port));
			break;

		case ICMP:
			assert(f->get_ip_payload_length() >= icmp->ICMP_MIN_HEADER_LENGTH && "Packet too short to fit ICMP header");
			icmp = (icmp_header_t *)ip->get_sdu();
			f->set_icmp_type(icmp->type);
			f->set_icmp_code(icmp->code);
			break;

		default:
			// No special handling
			break;
		}

		return f;
	}

	Sniffer::~Sniffer()
	{
		pcap_close(handle);
	}
}

