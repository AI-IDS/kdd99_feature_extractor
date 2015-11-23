#include <iostream>
#include <iomanip>
#include <fstream>
#include <string.h>
#include <new>          // std::bad_alloc
#include "Config.h"
#include "Sniffer.h"
#include "IpReassembler.h"
#include "ConversationReconstructor.h"
#include "StatsEngine.h"

using namespace std;
using namespace FeatureExtractor;

void usage();
void list_interfaces();
void parse_args(int argc, char **argv, Config *config);
void invalid_option(char *opt);
void invalid_option_value(char *opt, char *val);
void extract(Sniffer *sniffer, const Config *config);

int main(int argc, char **argv)
{
	try {
		Config config;
		parse_args(argc, argv, &config);

		if (config.get_files_count() == 0) {
			// Input from interface
			int inum = config.get_interface_num();
			if (config.should_print_filename())
				cout << "INTERFACE " << inum << endl;
			Sniffer *sniffer = new Sniffer(inum, &config);
			extract(sniffer, &config);
		}
		else {
			// Input from files
			int count = config.get_files_count();
			char **files = config.get_files_values();
			for (int i = 0; i < count; i++) {
				if (config.should_print_filename())
					cout << "FILE '" << files[i] << "'" << endl;

				Sniffer *sniffer = new Sniffer(files[i], &config);
				extract(sniffer, &config);
			}
		}
	}
	catch (std::bad_alloc& ba)	// Inform when memory limit reached
	{
		std::cerr << "Error allocating memory (Exception bad_alloc): " << ba.what() << '\n';
		return -1;
	}

	return 0;
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

		// IP Reassembly
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

			cf->print(config->should_print_extra_features());
			delete cf;
		}
	}
}

void usage()
{
	cout << "Usage: extractor [OPTION] [FILE]..." << endl
		<< " -h, --help    Display this usage  " << endl
		<< " -l, --list    List interfaces  " << endl
		<< " -i   NUMBER   Capture from interface with given number (default 1)" << endl
		<< " -p   MS       PCAP read timeout in ms (default 1000)" << endl
		<< " -e            Print extra features(IPs, ports, end timestamp)" << endl
		<< " -v            Print filename/interface number before parsing each file" << endl
		<< " -o   FILE     Write all output to FILE instead of standard output" << endl
		<< " -a   BYTES    Additional frame length to be add to each frame in bytes" << endl
		<< "                 (e.g. 4B Ethernet CRC) (default 0)" << endl
		<< " -ft  SECONDS  IP reassembly timeout (default 30)" << endl
		<< " -fi  MS       Max time between timed out IP fragments lookups in ms (default 1000)" << endl
		<< " -tst SECONDS  TCP SYN timeout for states S0, S1 (default 120)" << endl
		<< " -tet SECONDS  TCP timeout for established connections (default 5days)  " << endl
		<< " -trt SECONDS  TCP RST timeout for states REJ, RSTO, RSTR, RSTOS0 (default 10)" << endl
		<< " -tft SECONDS  TCP FIN timeout for states S2, S3 (default 120)" << endl
		<< " -tlt SECONDS  TCP last ACK timeout (default 30)" << endl
		<< " -ut  SECONDS  UDP timeout  (default 180)" << endl
		<< " -it  SECONDS  ICMP timeout  (default 30)" << endl
		<< " -ci  MS       Max time between timed out connection lookups in ms (default 1000)" << endl
		<< " -t   MS       Time window size in ms (default 2000)" << endl
		<< " -c   NUMBER   Count window size (default 100)" << endl
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

void parse_args(int argc, char **argv, Config *config)
{
	int i;

	// Options
	for (i = 1; i < argc && argv[i][0] == '-'; i++) {
		int len = strlen(argv[i]);
		if (len < 2)
			invalid_option(argv[i]);

		// Second character
		char *endptr;
		long num;
		std::ofstream out_stream;
		switch (argv[i][1]) {
		case '-': // Long option
			if (strcmp(argv[i], "--help") == 0) {
				usage();
				exit(0);
			}
			if (strcmp(argv[i], "--list") == 0) {
				list_interfaces();
				exit(0);
			}

			invalid_option(argv[i]);
			break;

		case 'h':
			usage();
			exit(0);
			break;

		case 'l':
			list_interfaces();
			exit(0);
			break;

		case 'i':
			if (len == 2) {
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "");

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i]);

				config->set_interface_num(num);
			}
			else if (len == 3 && argv[i][2] == 't') {	// Option -it
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "");

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i]);

				config->set_icmp_timeout(num);
			}
			else {
				invalid_option(argv[i]);
			}
			break;

		case 'e':
			if (len != 2)
				invalid_option(argv[i]);

			config->set_print_extra_features(true);
			break;

		case 'v':
			if (len != 2)
				invalid_option(argv[i]);

			config->set_print_filename(true);
			break;

		case 'o':
			if (len != 2)
				invalid_option(argv[i]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "");

			out_stream = ofstream(argv[i]);
			// streambuf *coutbuf = std::cout.rdbuf(); //save old buf
			cout.rdbuf(out_stream.rdbuf());		//redirect std::cout
			break;

		case 'p':
			if (len != 2)
				invalid_option(argv[i]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "");

			num = strtol(argv[i], &endptr, 10);
			if (endptr < argv[i] + strlen(argv[i]))
				invalid_option_value(argv[i - 1], argv[i]);

			config->set_pcap_read_timeout(num);
			break;

		case 'a':
			if (len != 2)
				invalid_option(argv[i]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "");

			num = strtol(argv[i], &endptr, 10);
			if (endptr < argv[i] + strlen(argv[i]))
				invalid_option_value(argv[i - 1], argv[i]);

			config->set_additional_frame_len(num);
			break;

		case 'c':
			if (len == 2) {
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "");

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i]);

				config->set_count_window_size(num);
			}
			else if (len == 3 && argv[i][2] == 'i') {	// Option -ci
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "");

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i]);

				config->set_conversation_check_interval_ms(num);
			}
			else {
				invalid_option(argv[i]);
			}
			break;

		case 'u':
			// Limit to '-ut'
			if (len != 3 || argv[i][2] != 't')
				invalid_option(argv[i]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "");

			num = strtol(argv[i], &endptr, 10);
			if (endptr < argv[i] + strlen(argv[i]))
				invalid_option_value(argv[i - 1], argv[i]);

			config->set_udp_timeout(num);
			break;

		case 'f':
			if (len != 3)
				invalid_option(argv[i]);

			// Third character
			switch (argv[i][2]) {
			case 't':
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "");

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i]);

				config->set_ipfrag_timeout(num);
				break;

			case 'i':
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "");

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i]);

				config->set_ipfrag_check_interval_ms(num);
				break;

			default:
				invalid_option(argv[i]);
				break;
			}
			break;

		case 't':
			if (len == 2) {
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "");

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i]);

				config->set_time_window_size_ms(num);
			}
			else if (len == 4 && argv[i][3] == 't') { // Limit to '-t?t'
				// Third character
				switch (argv[i][2]) {
				case 's':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "");

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i]);

					config->set_tcp_syn_timeout(num);
					break;

				case 'e':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "");

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i]);

					config->set_tcp_estab_timeout(num);
					break;

				case 'r':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "");

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i]);

					config->set_tcp_rst_timeout(num);
					break;

				case 'f':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "");

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i]);

					config->set_tcp_fin_timeout(num);
					break;

				case 'l':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "");

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i]);

					config->set_tcp_last_ack_timeout(num);
					break;

				default:
					invalid_option(argv[i]);
					break;
				}
			}
			else {
				invalid_option(argv[i]);
			}
			break;


		default:
			invalid_option(argv[i]);
			break;
		}

	}

	// File list
	int file_cnt = argc - i;
	config->set_files_count(file_cnt);
	if (file_cnt) {
		config->set_files_values(&argv[i]);
	}
}

void invalid_option(char *opt)
{
	cout << "Invalid option '" << opt << "'" << endl << endl;
	usage();
	exit(-1);
}

void invalid_option_value(char *opt, char *val)
{
	cout << "Invalid value '" << val << "' for option '" << opt << "'" << endl << endl;
	usage();
	exit(-1);
}