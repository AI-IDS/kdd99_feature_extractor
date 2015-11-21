#include <iostream>
#include <iomanip>
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





	struct timeval tv;
	tv.tv_sec = 10000;
	tv.tv_usec = 20000;

	Timestamp ts1(tv);
	Timestamp ts2 = ts1 - (2000 * 1); //should be 2 sec ago

	cout << endl << "orig=" << ts1.get_secs() << " new=" << ts2.get_secs() << endl;
	ts2 = ts1 + (2000 * 1); //should be 2 sec ago

	cout << endl << "orig=" << ts1.get_secs() << " new=" << ts2.get_secs() << endl;

	return;
}

void usage();
void list_interfaces();
void extract(Sniffer *sniffer, bool print_extra_features = true);

int main(int argc, char* argv[])
{
	Sniffer *sniffer = NULL;

	// TODO: usage/help, more input files, move main cycle to function
	/*
		extractor [OPTION] [FILE]...
		-i interface_num
		-e print extra features (IPs, ports, end time)
		[timeouts]
		[window settings]

		*/

	// test
	//usage();
	//list_interfaces();

	// TODO: arg: timouts, intervals
	/*
	uint32_t ipfrag;
	uint32_t ipfrag_check_interval;

	uint32_t tcp_syn;		// S0, S1
	uint32_t tcp_estab;		// ESTAB
	uint32_t tcp_rst;		// REJ, RSTO, RSTR, RSTOS0
	uint32_t tcp_fin;		// S2, S3
	uint32_t tcp_last_ack;	// S2F, S2F
	uint32_t udp;
	uint32_t icmp;
	uint32_t conversation_check_interval;



	*/

	if (argc <= 1) {
		sniffer = new Sniffer(1);
	}
	else {
		int inum = atoi(argv[1]);
		if (inum && to_string(inum) == argv[1]) {
			sniffer = new Sniffer(inum);
		}
		else {
			sniffer = new Sniffer(argv[1]);
		}

	}

	//sniffer = new Sniffer("ip_frag_source.pcap");
	//sniffer = new Sniffer("ssh.pcap");
	//sniffer = new Sniffer("ssh_student.pcap");
	//sniffer = new Sniffer("t.cap");

	debug_test();

	extract(sniffer);

	return 0;

	//-------------------------------
	// OLD outp.

	IpReassembler reasm;
	ConversationReconstructor conv_reconstructor;
	StatsEngine stats_engine;

	bool has_more_traffic = true;
	while (has_more_traffic) {
		Packet *datagr = nullptr;

		IpFragment *frag = sniffer->next_frame();
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
			//cout << "==================================" << endl;
			//conv->print();
			//cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl << endl;

			//delete conv;

			// Derived features
			ConversationFeatures *cf = stats_engine.calculate_features(conv);
			conv = nullptr;

			//cf->print_human();
			cf->print();

			delete cf;
		}
	}


	//cout << endl;
	//system("pause");
	return 0;
}


void extract(Sniffer *sniffer, bool print_extra_features)
{
	IpReassembler reasm;
	ConversationReconstructor conv_reconstructor;
	StatsEngine stats_engine;

	bool has_more_traffic = true;
	while (has_more_traffic) {
		Packet *datagr = nullptr;

		// Get frame from sniffer
		IpFragment *frag = sniffer->next_frame();
		has_more_traffic = (frag != NULL);

		// I
		if (has_more_traffic)  {
			ip_field_protocol_t ip_proto = frag->get_ip_proto();
			if (ip_proto != TCP && ip_proto != UDP && ip_proto != ICMP)
				continue;

			datagr = reasm.reassemble(frag);
		}
		else {
			// If no more traffic, finish everything
			conv_reconstructor.finish_all_conversations();
		}

		// Pass datagrams/packets to conversation reconstruction engine
		if (datagr)
			conv_reconstructor.add_packet(datagr);

		// Output conversations
		Conversation *conv;
		while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
			ConversationFeatures *cf = stats_engine.calculate_features(conv);
			conv = nullptr;		// Should not be used anymore, object will commit suicide

			cf->print(print_extra_features);
			delete cf;
		}
	}
}

void usage()
{
	cout << "Usage: extractor [OPTION] [FILE]..." << endl
		<< "  -l, --list \tList interfaces" << endl
		<< "  -i interface_num" << endl
		<< "  -e \tPrint extra features(IPs, ports, end timestamp)" << endl
		<< "  [timeouts]" << endl	// TODO
		<< "  [window settings]" << endl	// TODO
		<< "  [intervals]" << endl	// TODO
		<< endl;
}

void list_interfaces()
{

	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	// Retrieve the device list
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		cerr << "Error in pcap_findalldevs: " << errbuf << endl;
		exit(-1);
	}

	// Print the list
	for (d = alldevs, i = 1; d; d = d->next, i++) {
		
		cout << i << ". "
			<< setiosflags(ios_base::left) << setw(40) << d->description
			<< "\t[" << d->name << ']' << endl;
	}
	cout << endl;

	// Free the device list
	pcap_freealldevs(alldevs);
}
