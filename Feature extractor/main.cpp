
//#pragma warning(default:4265)
#include <iostream>
#include <cstdlib>
#include "IpReassembler.h"
#include "PcapReader.h"

using namespace std;
using namespace FeatureExtractor;

int main(int argc, char* argv[])
{
	PcapReader *p = NULL;


	//// TCP flag debug
	//tcp_field_flags_t tcp_flags;
	//tcp_flags.flags = 0x11;
	//cout << (tcp_flags.fin() ? "F" : "-");
	//cout << (tcp_flags.syn() ? "S" : "-");
	//cout << (tcp_flags.rst() ? "R" : "-");
	//cout << (tcp_flags.psh() ? "P" : "-");
	//cout << " ";
	//cout << (tcp_flags.ack() ? "A" : "-");
	//cout << (tcp_flags.urg() ? "U" : "-");
	//cout << (tcp_flags.ece() ? "E" : "-");
	//cout << (tcp_flags.cwr() ? "C" : "-");
	//cout << endl;
	//system("pause");
	//return 0;

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

	//p = new PcapReader("ip_frag_source.pcap");
	p = new PcapReader("t.cap");

	IpReassembler reasm;
	Packet *datagr;

	IpFragment *frag;
	while ((frag = p->next_frame()) != NULL) {
		frag->print();
		datagr = reasm.reassemble(frag);
		if (datagr && datagr->get_frame_count() > 1) {
			cout << "==================================" << endl;
			datagr->print();
			cout << "^^^^^^^^^^^^^" << endl << endl;
		}


		delete frag;
	}
		

	cout << endl;
	//system("pause");
	return 0;
}