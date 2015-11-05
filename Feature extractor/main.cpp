	
//#pragma warning(default:4265)
#include <iostream>
#include <cstdlib>
#include <string>
#include "PcapReader.h"
#include "IpReassembler.h"
#include "ConversationReconstructor.h"


using namespace std;
using namespace FeatureExtractor;

void debug_test()
{
	return;

	struct timeval tv;
	tv.tv_sec = 10000;
	tv.tv_usec = 20000;

	Timestamp ts1(tv);
	Timestamp ts2;

	cout << endl << "---- before s =" << ts2.get_secs() << " new=" << ts1.get_secs() << endl;

	ts2 = ts1;
	cout << "after s =" << ts2.get_secs() << endl;
	return;
}

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
		if (inum && to_string(inum) == argv[1]) {
			p = new PcapReader(inum);
		}
		else {
			p = new PcapReader(argv[1]);
		}

	}

	debug_test();

	//PcapReader p(1);
	//PcapReader p("ip_frag_source.pcap");
	//PcapReader p("ip_frag_source.pcap");

	//p = new PcapReader("ip_frag_source.pcap");
	//p = new PcapReader("ssh.pcap");
	//p = new PcapReader("ssh_student.pcap");
	//p = new PcapReader("t.cap");

	IpReassembler reasm;
	ConversationReconstructor conn_reconstructor;
	Packet *datagr;

	IpFragment *frag;
	Conversation *conv;
	while ((frag = p->next_frame()) != NULL) {
		//frag->print();
		ip_field_protocol_t ip_proto = frag->get_ip_proto();
		if (ip_proto != TCP && ip_proto != UDP && ip_proto != ICMP)
			continue;

		datagr = reasm.reassemble(frag);
		if (datagr) {
			// WTF debug
			//cout << "----------------------------------" << endl;
			//datagr->print();
			//cout << "^^^^^^^^^^^^^" << endl << endl;
			//cout << endl;
			
			conv = conn_reconstructor.add_packet(datagr);
			if (conv) {
				cout << "==================================" << endl;
				conv->print();
				//cout << "^^^^^^^^^^^^^" << endl << endl;

				delete conv;
			}
		}


		delete frag;
	}
		

	cout << endl;
	//system("pause");
	return 0;
}