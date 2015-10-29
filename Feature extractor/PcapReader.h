#pragma once

#include "IpFragment.h"
// Wrap pcap.h in extern "C"
// Bug in win WpdPack_4_1_2 http://www.winpcap.org/pipermail/winpcap-bugs/2013-November/001760.html
extern "C" {
#include <pcap.h>
}


namespace FeatureExtractor {
	class PcapReader
	{
		pcap_t *handle;

		// Snapshot length = 14B Eth2 header + 60B - max IP header length + 20 TCP basic header
		static const size_t SNAPLEN = 94;

		// Additional length = 4B = Ethernet II CRC size (CRC is not part of libpcap packet capture)
		static const size_t ADDITIONAL_LEN = 0;// 4;// zero for debug

	public:
		PcapReader(char *fname);
		PcapReader(int inum);
		~PcapReader();

		IpFragment *next_frame();

	};
}

