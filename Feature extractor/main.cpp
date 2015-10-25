
#pragma warning(default:4265)
#include <iostream>
#include <cstdlib>
//#include <pcap.h>
#include "PcapReader.h"

using namespace std;
using namespace FeatureExtractor;

int main(int argc, char* argv[])
{
	PcapReader *p = NULL;


	if (argc <= 1) {
		p = new PcapReader(1);
	}
	else {
		int inum = atoi(argv[1]);
		if (inum) {
			p = new PcapReader(inum);
		}
		else {
			p = new PcapReader(argv[1]);
		}

	}

	//PcapReader p(1);
	//PcapReader p("ip_frag_source.pcap");
	//PcapReader p("ip_frag_source.pcap");

//	p = new PcapReader("ip_frag_source.pcap");

	while (p->next_frame())
		;

	cout << endl;
	//system("pause");
	return 0;
}