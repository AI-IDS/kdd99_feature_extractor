#pragma once

#include "IpFragment.h"
// Bug in win WpdPack_4_1_2: On line 69 of pcap-stdinc.h, 'inline' is re-defined
// http://www.winpcap.org/pipermail/winpcap-bugs/2013-November/001760.html
#include <pcap.h>

namespace FeatureExtractor {
	/**
	 * Network traffic sniffer & frame parser
	 */
	class Sniffer
	{
		pcap_t *handle;

		// Snapshot length (in bytes) - limited to improve performace
		// 96B = 14B Eth2 header + 60B max IP header length + 20 TCP basic header
		// This must be enlarged ("unlimited"), if deep packet inspection 
		// (i.e. payload analysis) is employed.
		static const size_t SNAPLEN = 94;

		// Additional length for each frame 
		// For example 4B = Ethernet II CRC/FSC size (if it is not part of libpcap packet capture)
		// The above can depend on network adapter (see http://serverfault.com/a/521480/322790)
		// Value 0 should lead to same result as you can see in wireshark
		size_t additional_frame_length;

	public:
		Sniffer(char *fname, size_t additional_frame_length = 0);
		Sniffer(int inum, size_t additional_frame_length = 0);
		~Sniffer();

		IpFragment *next_frame();

	};
}

