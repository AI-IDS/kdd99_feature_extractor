
//#pragma warning(default:4265)
#include <iostream>
#include <cstdlib>
#include <string>
#include "Sniffer.h"
#include "IpReassembler.h"
#include "ConversationReconstructor.h"
#include "StatsEngine.h"


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
	Sniffer *p = NULL;


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
		p = new Sniffer(1);
	}
	else {
		int inum = atoi(argv[1]);
		if (inum && to_string(inum) == argv[1]) {
			p = new Sniffer(inum);
		}
		else {
			p = new Sniffer(argv[1]);
		}

	}

	debug_test();

	//p = new Sniffer("ip_frag_source.pcap");
	//p = new Sniffer("ssh.pcap");
	//p = new Sniffer("ssh_student.pcap");
	//p = new Sniffer("t.cap");

	IpReassembler reasm;
	ConversationReconstructor conv_reconstructor;
	StatsEngine stats_engine;

	bool has_more_traffic = true;
	while (has_more_traffic) {
		Packet *datagr = nullptr;

		IpFragment *frag = p->next_frame();
		has_more_traffic = (frag != NULL);

		if (has_more_traffic)  {
			//frag->print();
			ip_field_protocol_t ip_proto = frag->get_ip_proto();
			if (ip_proto != TCP && ip_proto != UDP && ip_proto != ICMP)
				continue;

			datagr = reasm.reassemble(frag);
		}
		else {
			conv_reconstructor.finish_all_conversations();
		}

		if (datagr) {
			//// WTF debug
			//cout << "----------------------------------" << endl;
			//datagr->print();
			//cout << "----------------------------------" << endl << endl;

			conv_reconstructor.add_packet(datagr);
		}

		// Output conversations
		Conversation *conv;
		while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
			cout << "==================================" << endl;
			conv->print();
			//cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl << endl;

			//delete conv;

			// Derived features
			ConversationFeatures *cf = stats_engine.calculate_features(conv);

			delete cf;
		}
	}


	cout << endl;
	//system("pause");
	return 0;
}