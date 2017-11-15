#include <iostream>
#include <iomanip>
#include <fstream>
#include <string.h>
#include <new>          // std::bad_alloc
#include <csignal>
#include <cstdlib>
#include <assert.h>

#include "Config.h"
#include "Sniffer.h"
#include "IpReassembler.h"
#include "ConversationReconstructor.h"
#include "StatsEngine.h"

using namespace std;
using namespace FeatureExtractor;

static volatile bool temination_requested = false;

void signal_handler(int signum);
void usage(const char *name);
void list_interfaces();
void parse_args(int argc, char **argv, Config *config);
void invalid_option(const char *opt, const char *progname);
void invalid_option_value(const char *opt, const char *val, const char *progname);
void extract(Sniffer *sniffer, const Config *config, bool is_running_live);

int main(int argc, char **argv)
{
	// Register signal handler for termination
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
#ifdef SIGBREAK
	signal(SIGBREAK, signal_handler);
#endif

	try {
		Config config;
		parse_args(argc, argv, &config);

		if (config.get_files_count() == 0) {
			// Input from interface
			int inum = config.get_interface_num();
			if (config.should_print_filename())
				cout << "INTERFACE " << inum << endl;
			Sniffer *sniffer = new Sniffer(inum, &config);
			extract(sniffer, &config, true);
		}
		else {
			// Input from files
			int count = config.get_files_count();
			char **files = config.get_files_values();
			for (int i = 0; i < count; i++) {
				if (config.should_print_filename())
					cout << "FILE '" << files[i] << "'" << endl;

				Sniffer *sniffer = new Sniffer(files[i], &config);
				extract(sniffer, &config, false);
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

void signal_handler(int signum)
{
	cerr << "Terminating extractor (signal " << signum << " received)" << endl;
	temination_requested = true;
}

void extract(Sniffer *sniffer, const Config *config, bool is_running_live)
{
	IpReassembler reasm;
	ConversationReconstructor conv_reconstructor;
	StatsEngine stats_engine(config);

	bool has_more_traffic = true;
	while (!temination_requested && (has_more_traffic || is_running_live)) {

		// Get frame from sniffer
		IpFragment *frag = sniffer->next_frame();
		has_more_traffic = (frag != NULL);

		
		Packet *datagr = nullptr;
		if (has_more_traffic) {
			// Do some assertion about the type of packet just to be sure
			// If sniffer's filter fails to fulfill this assertion, "continue" can be used here
			eth_field_type_t eth_type = frag->get_eth_type();
			ip_field_protocol_t ip_proto = frag->get_ip_proto();
			assert((eth_type == IPV4 && (ip_proto == TCP || ip_proto == UDP || ip_proto == ICMP))
				&& "Sniffer returned packet that is not (TCP or UDP or ICMP)");

			Timestamp now = frag->get_end_ts();

			// IP Reassembly, frag must not be used after this
			datagr = reasm.reassemble(frag);

			// Conversation reconstruction
			if (datagr) {
				conv_reconstructor.add_packet(datagr);
			}
			else {
				// Tell conversation reconstruction just how the time goes on
				conv_reconstructor.report_time(now);
			}
		}

		// Output timedout conversations 
		Conversation *conv;
		while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
			ConversationFeatures *cf = stats_engine.calculate_features(conv);
			conv = nullptr;		// Should not be used anymore, object will commit suicide

			cf->print(config->should_print_extra_features());
			delete cf;
		}
	}

	// If no more traffic, finish everything
	conv_reconstructor.finish_all_conversations();

	// Output leftover conversations
	Conversation *conv;
	while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
		ConversationFeatures *cf = stats_engine.calculate_features(conv);
		conv = nullptr;

		cf->print(config->should_print_extra_features());
		delete cf;
	}
}

void usage(const char *name)
{
	// Option '-' orignaly meant to use big read timeouts and exit on first timeout. Other approach used
	// because original approach did not work (does this option make sense now?).
	cout << "KDD'99-like feature extractor" << endl
		<< "Build time : " << __DATE__ << " " << __TIME__ << endl << endl
		<< "Usage: " << name << " [OPTION]... [FILE]" << endl
		<< " -h, --help    Display this usage  " << endl
		<< " -l, --list    List interfaces  " << endl
		<< " -i   NUMBER   Capture from interface with given number (default 1)" << endl
		<< " -p   MS       libpcap network read timeout in ms (default 1000)" << endl
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
		exit(1);
	}

	// Print the list
	for (d = alldevs, i = 1; d; d = d->next, i++) {

		cout << i << ". "
			<< setiosflags(ios_base::left) << setw(40) << (char *)((d->description != 0)? d->description:"NULL")
			<< "\t[" << d->name << ']' << endl;
	}
	cout << endl;

	// Free the device list
	pcap_freealldevs(alldevs);
}

// TODO: code snippets in usage() can be reused function/macro
void parse_args(int argc, char **argv, Config *config)
{
	int i;

	// Options
	for (i = 1; i < argc && argv[i][0] == '-'; i++) {
		size_t len = strlen(argv[i]);
		if (len < 2)
			invalid_option(argv[i], argv[0]);

		// Second character
		char *endptr;
		long num;
		std::ofstream out_stream;
		switch (argv[i][1]) {
		case '-': // Long option
			if (strcmp(argv[i], "--help") == 0) {
				usage(argv[0]);
				exit(0);
			}
			if (strcmp(argv[i], "--list") == 0) {
				list_interfaces();
				exit(0);
			}

			invalid_option(argv[i], argv[0]);
			break;

		case 'h':
			usage(argv[0]);
			exit(0);
			break;

		case 'l':
			list_interfaces();
			exit(0);
			break;

		case 'i':
			if (len == 2) {
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "", argv[0]);

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i], argv[0]);

				config->set_interface_num(num);
			}
			else if (len == 3 && argv[i][2] == 't') {	// Option -it
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "", argv[0]);

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i], argv[0]);

				config->set_icmp_timeout(num);
			}
			else {
				invalid_option(argv[i], argv[0]);
			}
			break;

		case 'e':
			if (len != 2)
				invalid_option(argv[i], argv[0]);

			config->set_print_extra_features(true);
			break;

		case 'v':
			if (len != 2)
				invalid_option(argv[i], argv[0]);

			config->set_print_filename(true);
			break;

		case 'o':
			if (len != 2)
				invalid_option(argv[i], argv[0]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "", argv[0]);

			out_stream.open(argv[i]);
			// streambuf *coutbuf = std::cout.rdbuf(); //save old buf
			cout.rdbuf(out_stream.rdbuf());		//redirect std::cout
			break;

		case 'p':
			if (len != 2)
				invalid_option(argv[i], argv[0]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "", argv[0]);

			num = strtol(argv[i], &endptr, 10);
			if (endptr < argv[i] + strlen(argv[i]))
				invalid_option_value(argv[i - 1], argv[i], argv[0]);

			config->set_pcap_read_timeout(num);
			break;

		case 'a':
			if (len != 2)
				invalid_option(argv[i], argv[0]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "", argv[0]);

			num = strtol(argv[i], &endptr, 10);
			if (endptr < argv[i] + strlen(argv[i]))
				invalid_option_value(argv[i - 1], argv[i], argv[0]);

			config->set_additional_frame_len(num);
			break;

		case 'c':
			if (len == 2) {
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "", argv[0]);

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i], argv[0]);

				config->set_count_window_size(num);
			}
			else if (len == 3 && argv[i][2] == 'i') {	// Option -ci
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "", argv[0]);

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i], argv[0]);

				config->set_conversation_check_interval_ms(num);
			}
			else {
				invalid_option(argv[i], argv[0]);
			}
			break;

		case 'u':
			// Limit to '-ut'
			if (len != 3 || argv[i][2] != 't')
				invalid_option(argv[i], argv[0]);

			if (argc <= ++i)
				invalid_option_value(argv[i - 1], "", argv[0]);

			num = strtol(argv[i], &endptr, 10);
			if (endptr < argv[i] + strlen(argv[i]))
				invalid_option_value(argv[i - 1], argv[i], argv[0]);

			config->set_udp_timeout(num);
			break;

		case 'f':
			if (len != 3)
				invalid_option(argv[i], argv[0]);

			// Third character
			switch (argv[i][2]) {
			case 't':
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "", argv[0]);

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i], argv[0]);

				config->set_ipfrag_timeout(num);
				break;

			case 'i':
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "", argv[0]);

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i], argv[0]);

				config->set_ipfrag_check_interval_ms(num);
				break;

			default:
				invalid_option(argv[i], argv[0]);
				break;
			}
			break;

		case 't':
			if (len == 2) {
				if (argc <= ++i)
					invalid_option_value(argv[i - 1], "", argv[0]);

				num = strtol(argv[i], &endptr, 10);
				if (endptr < argv[i] + strlen(argv[i]))
					invalid_option_value(argv[i - 1], argv[i], argv[0]);

				config->set_time_window_size_ms(num);
			}
			else if (len == 4 && argv[i][3] == 't') { // Limit to '-t?t'
				// Third character
				switch (argv[i][2]) {
				case 's':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "", argv[0]);

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i], argv[0]);

					config->set_tcp_syn_timeout(num);
					break;

				case 'e':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "", argv[0]);

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i], argv[0]);

					config->set_tcp_estab_timeout(num);
					break;

				case 'r':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "", argv[0]);

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i], argv[0]);

					config->set_tcp_rst_timeout(num);
					break;

				case 'f':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "", argv[0]);

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i], argv[0]);

					config->set_tcp_fin_timeout(num);
					break;

				case 'l':
					if (argc <= ++i)
						invalid_option_value(argv[i - 1], "", argv[0]);

					num = strtol(argv[i], &endptr, 10);
					if (endptr < argv[i] + strlen(argv[i]))
						invalid_option_value(argv[i - 1], argv[i], argv[0]);

					config->set_tcp_last_ack_timeout(num);
					break;

				default:
					invalid_option(argv[i], argv[0]);
					break;
				}
			}
			else {
				invalid_option(argv[i], argv[0]);
			}
			break;

		default:
			invalid_option(argv[i], argv[0]);
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

void invalid_option(const char *opt, const char *progname)
{
	cout << "Invalid option '" << opt << "'" << endl << endl;
	usage(progname);
	exit(1);
}

void invalid_option_value(const char *opt, const char *val, const char *progname)
{
	cout << "Invalid value '" << val << "' for option '" << opt << "'" << endl << endl;
	usage(progname);
	exit(1);
}