#pragma once

// Wrap pcap.h in extern "C"
// Bug in win WpdPack_4_1_2 http://www.winpcap.org/pipermail/winpcap-bugs/2013-November/001760.html
extern "C" {
#include <pcap.h>
}

#include "Frame.h"

class PcapReader
{
	pcap_t *handle;

	// Snapshot length
	static const int  MAX_SNAPLEN;

public:
	PcapReader(char *fname);
	PcapReader(int inum);
	~PcapReader();

	int next_frame();

};

