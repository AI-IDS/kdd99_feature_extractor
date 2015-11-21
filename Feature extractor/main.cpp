#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <string>
#include "Config.h"
#include "Sniffer.h"
#include "IpReassembler.h"
#include "ConversationReconstructor.h"
#include "StatsEngine.h"

using namespace std;
using namespace FeatureExtractor;


void usage();
void list_interfaces();
void parse_args(int argc, char *argv[], Config *config);
void extract(Sniffer *sniffer, const Config *config);

int main(int argc, char **argv)
{
	Config config;

	parse_args(argc, argv, &config);

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

	// TODO: arg: timouts, intervals ... (config)



	// TODO: arg_parser(args, config)
	// - multiple files
	// - switch to print line with filename

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

	//debug_test();

	extract(sniffer, &config);

	return 0;
}


void parse_args(int argc, char *argv[], Config *config)
{

}

void extract(Sniffer *sniffer, const Config *config)
{
	IpReassembler reasm;
	ConversationReconstructor conv_reconstructor;
	StatsEngine stats_engine(config);

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

			cf->print(config->get_print_extra_features());
			delete cf;
		}
	}
}


/*
TODO:
l  list
h  help
? help
--help help
e print extra features

-  int files_c;
-  char *files_v;
i  int interface_num;
a  size_t additional_frame_len;

ft  uint32_t ipfrag_timeout;
fi  uint32_t ipfrag_check_interval;

tst  uint32_t tcp_syn_timeout;
tet  uint32_t tcp_estab_timeout;
trt  uint32_t tcp_rst_timeout;
tft  uint32_t tcp_fin_timeout;
tlt  uint32_t tcp_last_ack_timeout;
ut  uint32_t udp_timeout;
it  uint32_t icmp_timeout;
ci  uint32_t conversation_check_interval;

w  unsigned int time_window_size_ms;
c  unsigned int count_window_size;
*/
void usage()
{
	cout << "Usage: extractor [OPTION] [FILE]..." << endl
		<< " -h, --help   Display this usage  " << endl
		<< " -l, --list    List interfaces  " << endl
		<< " -i   NUMBER   Capture from interface with given number  " << endl
		<< " -e            Print extra features(IPs, ports, end timestamp)  " << endl
		<< " -a   BYTES    Additional frame length to be add to each frame in bytes  " << endl
		<< "                 (e.g. 4B Ethernet CRC)  " << endl
		<< " -ft  SECONDS  IP reassembly timeout (default 30)" << endl
		<< " -fi  SECONDS  Max time between timed out IP fragments lookups (default 1) " << endl
		<< " -tst SECONDS  TCP SYN timeout for states S0, S1 (default 120)" << endl
		<< " -tet SECONDS  TCP timeout for established connections (default 5days)  " << endl
		<< " -trt SECONDS  TCP RST timeout for states REJ, RSTO, RSTR, RSTOS0 (default 10)  " << endl
		<< " -tft SECONDS  TCP FIN timeout for states S2, S3 (default 120)  " << endl
		<< " -tlt SECONDS  TCP last ACK timeout (default 30)" << endl
		<< " -ut  SECONDS  UDP timeout  (default 180)" << endl
		<< " -it  SECONDS  ICMP timeout  (default 30)" << endl
		<< " -ci  SECONDS  Max time between timed out connection lookups (default 1)" << endl
		<< " -w   MS       Time window size in ms (default 2000)" << endl
		<< " -c   NUMBER   Count window size (default 100)  " << endl
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
