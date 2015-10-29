
//#pragma warning(default:4265)
#include <iostream>
#include <cstdlib>
#include "PcapReader.h"
#include "IpReassembler.h"
#include "TcpConncetionReconstructor.h"


using namespace std;
using namespace FeatureExtractor;

void debug_test()
{
	return;

	TcpConncetionReconstructor rec;
	Packet p;
	p.set_src_ip(246853523);
	p.set_dst_ip(832548755);
	p.set_src_port(57642);
	p.set_dst_port(22);

	rec.add_packet(&p);


	p.set_src_ip(832548755);
	p.set_dst_ip(246853523);
	p.set_src_port(22);
	p.set_dst_port(57642);
	rec.add_packet(&p);
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
		if (inum) {
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
	//p = new PcapReader("t.cap");

	IpReassembler reasm;
	TcpConncetionReconstructor conn_reconstructor;
	Packet *datagr;

	IpFragment *frag;
	TcpConnection *conn;
	while ((frag = p->next_frame()) != NULL) {
		//frag->print();
		datagr = reasm.reassemble(frag);
		if (datagr) {
			//cout << "----------------------------------" << endl;
			//datagr->print();
			//cout << "^^^^^^^^^^^^^" << endl << endl;
			//cout << endl;
			
			// TODO: only TCP
			conn = conn_reconstructor.add_packet(datagr);
			if (conn) {
				cout << "==================================" << endl;
				conn->print();
				cout << "^^^^^^^^^^^^^" << endl << endl;

				delete conn;
			}
		}


		delete frag;
	}
		

	cout << endl;
	//system("pause");
	return 0;
}