#include "Config.h"

namespace FeatureExtractor {
	/**
	 * Constructor for default timeout values:
	 * - IP Fragmentation timeout 30s (Linux default)
	 *		http://www.linuxinsight.com/proc_sys_net_ipv4_ipfrag_time.html
	 * - Other values derived from iptables doc
	 *		http://www.iptables.info/en/connection-state.html
	 */
	Config::Config()
		: files_c(0)
		, files_v(nullptr)
		, interface_num(1)
		, pcap_read_timeout(1000)
		, additional_frame_len(0)
		, ipfrag_timeout(30)
		, ipfrag_check_interval_ms(1000)
		, tcp_syn_timeout(120)
		, tcp_estab_timeout(5 * 24 * 3600) // 5 days
		, tcp_rst_timeout(10)
		, tcp_fin_timeout(120)
		, tcp_last_ack_timeout(30)
		, udp_timeout(180)
		, icmp_timeout(30)
		, conversation_check_interval_ms(1000)
		, time_window_size_ms(2000)
		, count_window_size(100)
		, print_extra_features(false)
		, print_filename(false)
	{
	}


	Config::~Config()
	{
	}

	int Config::get_files_count() const
	{
		return files_c;
	}
	void Config::set_files_count(int files_c)
	{
		this->files_c = files_c;
	}

	char **Config::get_files_values() const
	{
		return files_v;
	}
	void Config::set_files_values(char **files_v)
	{
		this->files_v = files_v;
	}

	int Config::get_interface_num() const
	{
		return interface_num;
	}
	void Config::set_interface_num(int interface_num)
	{
		this->interface_num = interface_num;
	}

	int Config::get_pcap_read_timeout() const
	{
		return pcap_read_timeout;
	}
	void Config::set_pcap_read_timeout(int pcap_read_timeout)
	{
		this->pcap_read_timeout = pcap_read_timeout;
	}

	size_t Config::get_additional_frame_len() const
	{
		return additional_frame_len;
	}
	void Config::set_additional_frame_len(size_t additional_frame_len)
	{
		this->additional_frame_len = additional_frame_len;
	}


	uint32_t Config::get_ipfrag_timeout() const
	{
		return ipfrag_timeout;
	}
	void Config::set_ipfrag_timeout(uint32_t ipfrag_timeout)
	{
		this->ipfrag_timeout = ipfrag_timeout;
	}

	uint32_t Config::get_ipfrag_check_interval_ms() const
	{
		return ipfrag_check_interval_ms;
	}
	void Config::set_ipfrag_check_interval_ms(uint32_t ipfrag_check_interval_ms)
	{
		this->ipfrag_check_interval_ms = ipfrag_check_interval_ms;
	}

	uint32_t Config::get_tcp_syn_timeout() const
	{
		return tcp_syn_timeout;
	}
	void Config::set_tcp_syn_timeout(uint32_t tcp_syn_timeout)
	{
		this->tcp_syn_timeout = tcp_syn_timeout;
	}

	uint32_t Config::get_tcp_estab_timeout() const
	{
		return tcp_estab_timeout;
	}
	void Config::set_tcp_estab_timeout(uint32_t tcp_estab_timeout)
	{
		this->tcp_estab_timeout = tcp_estab_timeout;
	}

	uint32_t Config::get_tcp_rst_timeout() const
	{
		return tcp_rst_timeout;
	}
	void Config::set_tcp_rst_timeout(uint32_t tcp_rst_timeout)
	{
		this->tcp_rst_timeout = tcp_rst_timeout;
	}

	uint32_t Config::get_tcp_fin_timeout() const
	{
		return tcp_fin_timeout;
	}
	void Config::set_tcp_fin_timeout(uint32_t tcp_fin_timeout)
	{
		this->tcp_fin_timeout = tcp_fin_timeout;
	}

	uint32_t Config::get_tcp_last_ack_timeout() const
	{
		return tcp_last_ack_timeout;
	}
	void Config::set_tcp_last_ack_timeout(uint32_t tcp_last_ack_timeout)
	{
		this->tcp_last_ack_timeout = tcp_last_ack_timeout;
	}

	uint32_t Config::get_udp_timeout() const
	{
		return udp_timeout;
	}
	void Config::set_udp_timeout(uint32_t udp_timeout)
	{
		this->udp_timeout = udp_timeout;
	}

	uint32_t Config::get_icmp_timeout() const
	{
		return icmp_timeout;
	}
	void Config::set_icmp_timeout(uint32_t icmp_timeout)
	{
		this->icmp_timeout = icmp_timeout;
	}

	uint32_t Config::get_conversation_check_interval_ms() const
	{
		return conversation_check_interval_ms;
	}
	void Config::set_conversation_check_interval_ms(uint32_t conversation_check_interval_ms)
	{
		this->conversation_check_interval_ms = conversation_check_interval_ms;
	}

	unsigned int Config::get_time_window_size_ms() const
	{
		return time_window_size_ms;
	}
	void Config::set_time_window_size_ms(unsigned int time_window_size_ms)
	{
		this->time_window_size_ms = time_window_size_ms;
	}

	unsigned int Config::get_count_window_size() const
	{
		return count_window_size;
	}
	void Config::set_count_window_size(unsigned int count_window_size)
	{
		this->count_window_size = count_window_size;
	}

	bool Config::should_print_extra_features() const
	{
		return print_extra_features;
	}
	void Config::set_print_extra_features(bool print_extra_features)
	{
		this->print_extra_features = print_extra_features;
	}

	bool Config::should_print_filename() const
	{
		return print_filename;
	}
	void Config::set_print_filename(bool print_filename)
	{
		this->print_filename = print_filename;
	}


}
