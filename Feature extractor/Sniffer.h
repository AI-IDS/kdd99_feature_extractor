#pragma once

#include "IpFragment.h"
#include "Config.h"
// Bug in win WpdPack_4_1_2: On line 69 of pcap-stdinc.h, 'inline' is re-defined
// http://www.winpcap.org/pipermail/winpcap-bugs/2013-November/001760.html
// Solved by including pcap.h after standard libs
#include <pcap.h>


namespace FeatureExtractor {
	/**
	 * Network traffic sniffer & frame parser
	 */
	class Sniffer
	{
		pcap_t *handle;

		// Snapshot length (in bytes) - limited to improve performace (value in .cpp)
		static const size_t SNAPLEN;

		// Snapshot length (in bytes) - limited to improve performace (value in .cpp)
		static const char *DEFAULT_FILTER;

		// Additional length for each frame 
		// For example 4B = Ethernet II CRC/FSC size (if it is not part of libpcap packet capture)
		// The above can depend on network adapter (see http://serverfault.com/a/521480/322790)
		// Value 0 should lead to same result as you can see in wireshark
		size_t additional_frame_length;

		void set_filter(const char *filter);


	public:
		Sniffer(const char *fname, const Config *config = new Config());
		Sniffer(int inum, const Config *config = new Config());
		~Sniffer();

		/**
		 * Returns next parsed headers L3 & L4 of next frame 
		 */
		IpFragment *next_frame();
	};
}

