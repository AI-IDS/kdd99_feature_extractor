#include <sstream>
#include <iostream>
#include "TcpConnection.h"


namespace FeatureExtractor {
	using namespace std;

	TcpConnection::TcpConnection()
		: Conversation()
	{
	}

	TcpConnection::TcpConnection(const FiveTuple *tuple)
		: Conversation(tuple)
	{
	}

	TcpConnection::TcpConnection(const Packet *packet)
		: Conversation(packet)
	{
	}


	TcpConnection::~TcpConnection()
	{
	}

	void TcpConnection::update_state(const Packet *packet)
	{
		// Is the packet from originator or responder?
		bool originator = (packet->get_src_ip() == five_tuple.get_src_ip());

		tcp_field_flags_t f = packet->get_tcp_flags();

		switch (state) {
		case INIT:
			if (f.syn() && f.ack())
				state = S4;
			else if (f.syn())
				state = S1;
			else
				state = OTH;
			break;

		case S0:
			if (originator) {
				if (f.rst())
					state = RSTOS0;
				else if (f.fin())
					state = SH;
			}
			else { // from responder
				if (f.rst())
					state = REJ;
				else if (f.syn() && f.ack())
					state = S1;
			}
			break;

		case S4:
			if (originator) {
				if (f.rst())
					state = RSTRH;
				else if (f.fin())
					state = SHR;
			}
			break;

		case S1:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.ack())
					state = ESTAB;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
			}
			break;

		case ESTAB:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.fin())
					state = S2;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
				else if (f.fin())
					state = S3;
			}
			break;

		case S2:
			if (originator) {
				if (f.rst())
					state = RSTO;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
				else if (f.fin())
					state = S2F;
			}
			break;

		case S3:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.fin())
					state = S3F;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
			}
			break;

		case S2F:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.ack())
					state = SF;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
			}
			break;

		case S3F:
			if (originator) {
				if (f.rst())
					state = RSTO;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
				else if (f.ack())
					state = SF;
			}
			break;

		default:
			break;

		}
	}

	bool TcpConnection::is_in_final_state() const
	{
		// Get state with internal states replaced
		switch (this->get_state())
		{
		case INIT:
		case S0:
		case S1:
		case S4:
		case ESTAB:
		case S2:
		case S3:
			return false;
			break;

		// States ended with RST should get additional timeout
		// to process delayed packets
		// TODO: consider adding RSTRH
		case REJ:
		case RSTO:
		case RSTR:
		case RSTOS0:
			return false;
			break;

		default:
			return true;
			break;
		}
		return true;
	}

	service_t TcpConnection::get_service() const
	{
		// Identify FTP data in active FTP can be identified by source port
		// TODO: passive FTP (only through FTP control payload inspection?)
		if (five_tuple.get_src_port() == 20) {
			return SRV_FTP_DATA;
		}

		// Service ports assigned according to IANA Service Name and Transport Protocol Port Number Registry
		// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
		switch (five_tuple.get_dst_port())
		{
		case 194: // Internet Relay Chat Protocol
		case 529: // IRC-SERV
		case 2218: // Bounzza IRC Proxy
		case 6665: // IRCU (6665-6669)
		case 6666:
		case 6668:
		case 6669:
		case 6697: // Internet Relay Chat via TLS/SSL   
			return SRV_IRC;
			break;

		case 6000: // X Window System (6000-6063)
		case 6001:
		case 6002:
		case 6003:
		case 6004:
		case 6005:
		case 6006:
		case 6007:
		case 6008:
		case 6009:
		case 6010:
		case 6011:
		case 6012:
		case 6013:
		case 6014:
		case 6015:
		case 6016:
		case 6017:
		case 6018:
		case 6019:
		case 6020:
		case 6021:
		case 6022:
		case 6023:
		case 6024:
		case 6025:
		case 6026:
		case 6027:
		case 6028:
		case 6029:
		case 6030:
		case 6031:
		case 6032:
		case 6033:
		case 6034:
		case 6035:
		case 6036:
		case 6037:
		case 6038:
		case 6039:
		case 6040:
		case 6041:
		case 6042:
		case 6043:
		case 6044:
		case 6045:
		case 6046:
		case 6047:
		case 6048:
		case 6049:
		case 6050:
		case 6051:
		case 6052:
		case 6053:
		case 6054:
		case 6055:
		case 6056:
		case 6057:
		case 6058:
		case 6059:
		case 6060:
		case 6061:
		case 6062:
		case 6063:
			return SRV_X11;
			break;

		case 210: // ANSI Z39.50
			return SRV_Z39_50;
			break;

		case 5190: // America-Online
		case 5191: // AmericaOnline1
		case 5192: // AmericaOnline2
		case 5193: // AmericaOnline3
		case 531: // AOL Instant Messenger
			return SRV_AOL;
			break;

		case 113: // Authentication Service
		case 31: // MSG Authentication
		case 56: // XNS Authentication
		case 222: // Berkeley rshd with SPX auth
		case 353: // NDSAUTH
		case 370: // codaauth2
		case 1615: // NetBill Authorization Server
		case 2139: // IAS-AUTH
		case 2147: // Live Vault Authentication
		case 2334: // ACE Client Auth
		case 2392: // Tactical Auth
		case 2478: // SecurSight Authentication Server (SSL)
		case 2821: // VERITAS Authentication Service
		case 3113: // CS-Authenticate Svr Port
		case 3207: // Veritas Authentication Port
		case 3710: // PortGate Authentication
		case 3799: // RADIUS Dynamic Authorization
		case 3810: // WLAN AS server
		case 3833: // AIPN LS Authentication
		case 3871: // Avocent DS Authorization
		case 4032: // VERITAS Authorization Service
		case 4129: // NuFW authentication protocol
		case 4373: // Remote Authenticated Command Service
		case 5067: // Authentx Service
		case 5635: // SFM Authentication Subsystem
		case 6268: // Grid Authentication
		case 6269: // Grid Authentication Alt
		case 7004: // AFS/Kerberos authentication service
		case 7847: // A product key authentication protocol made by CSO
		case 9002: // DynamID authentication
		case 19194: // UserAuthority SecureAgent
		case 27999: // TW Authentication/Key Distribution and
			return SRV_AUTH;
			break;

		case 179: // Border Gateway Protocol
			return SRV_BGP;
			break;

		case 530: // rpc
		case 165: // Xerox (xns-courier)
			return SRV_COURIER;
			break;

		case 105: // Mailbox Name Nameserver
			return SRV_CSNET_NS;
			break;

		case 84: // Common Trace Facility
			return SRV_CTF;
			break;

		case 13: // Daytime
			return SRV_DAYTIME;
			break;

		case 9: // Discard
			return SRV_DISCARD;
			break;

		case 53: // Domain Name Server
			return SRV_DOMAIN;
			break;

		case 7: // 
			return SRV_ECHO;
			break;

		case 520: // extended file name server
			return SRV_EFS;
			break;

		case 512: // remote process execution; authentication performed using passwords and UNIX login names
			return SRV_EXEC;
			break;

		case 79: // Finger
			return SRV_FINGER;
			break;

		case 21: // File Transfer Protocol [Control]
			return SRV_FTP;
			break;

		case 20: // File Transfer [Default Data] (TODO)
			return SRV_FTP_DATA;
			break;

		case 70: // Gopher
			return SRV_GOPHER;
			break;

		// TODO: service harvest port number
		//case: // 
		//	return SRV_HARVEST;
		//	break;

		case 101: // NIC Host Name Server
			return SRV_HOSTNAMES;
			break;

		case 80: // World Wide Web HTTP
		case 8008: // HTTP Alternate
		case 8080: // HTTP Alternate
			return SRV_HTTP;
			break;

		case 2784: // world wide web - development (www-dev)
			return SRV_HTTP_2784;
			break;

		case 443: // http protocol over TLS/SSL
			return SRV_HTTP_443;
			break;

		case 8001: // VCOM Tunnel(iana) / Commonly used for Internet radio streams such as SHOUTcast (wiki)
			return SRV_HTTP_8001;
			break;

		case 5813: // ICMPD
			return SRV_ICMP;
			break;

		case 143: // imap4 protocol over TLS/SSL (imaps)
		case 993: // imap4 protocol over TLS/SSL (imaps)
			return SRV_IMAP4;
			break;

		case 102: // ISO-TSAP Class 0
		case 309: // ISO Transport Class 2 Non-Control over TCP
			return SRV_ISO_TSAP;
			break;

		case 543: // klogin
			return SRV_KLOGIN;
			break;

		case 544: // krcmd
			return SRV_KSHELL;
			break;

		case 389: // Lightweight Directory Access Protocol
		case 636: // ldap protocol over TLS/SSL (was sldap) (ldaps)
			return SRV_LDAP;
			break;

		case 245: // LINK
			return SRV_LINK;
			break;

		case 513: // "remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify ""authentication domains"""
			return SRV_LOGIN;
			break;

		case 1911: // Starlight Networks Multimedia Transport Protocol
			return SRV_MTP;
			break;

		case 42: // Host Name Server
			return SRV_NAME;
			break;

		case 138: // NETBIOS Datagram Service
			return SRV_NETBIOS_DGM;
			break;

		case 137: // NETBIOS Name Service
			return SRV_NETBIOS_NS;
			break;

		case 139: // NETBIOS Session Service
			return SRV_NETBIOS_SSN;
			break;

		case 15: // Unassigned [was netstat]
			return SRV_NETSTAT;
			break;

		case 433: // NNSP
			return SRV_NNSP;
			break;

		case 119: // Network News Transfer Protocol
		case 563: // nntp protocol over TLS/SSL (was snntp)
			return SRV_NNTP;
			break;

		// TODO: service pm_dump port number
		//case: // 
		//	return SRV_PM_DUMP;
		//	break;

		case 109: // Post Office Protocol Version 2
			return SRV_POP_2;
			break;

		case 110: // Post Office Protocol Version 3
			return SRV_POP_3;
			break;

		case 515: // spooler
			return SRV_PRINTER;
			break;

		case 71: // Remote Job Service (netrjs-1)
		case 72: // Remote Job Service (netrjs-2)
		case 73: // Remote Job Service (netrjs-3)
		case 74: // Remote Job Service (netrjs-4)
			return SRV_REMOTE_JOB;
			break;

		case 5: // Remote Job Entry
		case 77: // any private RJE service
			return SRV_RJE;
			break;

		case 514: // "cmd like exec
			return SRV_SHELL;
			break;

		case 25: // Simple Mail Transfer
			return SRV_SMTP;
			break;

		case 66: // Oracle SQL*NET
		case 150: // SQL-NET
			return SRV_SQL_NET;
			break;

		case 22: // The Secure Shell (SSH) Protocol
			return SRV_SSH;
			break;

		case 111: // SUN Remote Procedure Call
			return SRV_SUNRPC;
			break;

		case 95: // SUPDUP
			return SRV_SUPDUP;
			break;

		case 11: // Active Users
			return SRV_SYSTAT;
			break;

		case 23: // Telnet
			return SRV_TELNET;
			break;

		case 37: // Time
			return SRV_TIME;
			break;

		case 540: // uucpd
		case 4031: // UUCP over SSL
			return SRV_UUCP;
			break;

		case 117: // UUCP Path Service
			return SRV_UUCP_PATH;
			break;

		case 175: // VMNET
			return SRV_VMNET;
			break;

		case 43: // Who Is
		case 4321: // Remote Who Is (rwhois)
			return SRV_WHOIS;
			break;



		default:
			// Private ports defined by IANA in RFC 6335 section 6:
			// Dynamic Ports, also known as the Private or Ephemeral Ports,
			// from 49152 - 65535 (never assigned)
			if (five_tuple.get_dst_port() >= 49152)
				return SRV_PRIVATE; // or other?
			else
				return SRV_OTHER;
			break;
		}

		return SRV_OTHER;
	}
}
