#pragma once

// Wrap pcap.h in extern "C"
// Bug in win WpdPack_4_1_2 http://www.winpcap.org/pipermail/winpcap-bugs/2013-November/001760.html
extern "C" {
#include <pcap.h>
}

#include "Frame.h"

namespace FeatureExtractor {
	class PcapReader
	{
		pcap_t *handle;

		// Snapshot length = 14B Eth2 header + 60B - max IP header length + 20 TCP basic header
		static const int SNAPLEN = 94;

	public:
		PcapReader(char *fname);
		PcapReader(int inum);
		~PcapReader();

		int next_frame();

	};
}

