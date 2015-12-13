#pragma once

#include "types.h"

namespace FeatureExtractor {

	/**
	 * Class to store timeout settings
	 *
	 * If not specified otherwise, all time values are meant to be in seconds.
	 */
	class Config
	{
		/**
		 * Frame sniffing & parsing
		 */
		int files_c;	// Count of files, if 0 interface number should be used
		char **files_v;
		int interface_num;
		int pcap_read_timeout;
		size_t additional_frame_len;

		/**
		 * IP reassembly
		 */
		uint32_t ipfrag_timeout;
		uint32_t ipfrag_check_interval_ms;

		/**
		 * Conversation reconstruction
		 */
		uint32_t tcp_syn_timeout;		// S0, S1
		uint32_t tcp_estab_timeout;		// ESTAB
		uint32_t tcp_rst_timeout;		// REJ, RSTO, RSTR, RSTOS0
		uint32_t tcp_fin_timeout;		// S2, S3
		uint32_t tcp_last_ack_timeout;	// S2F, S2F
		uint32_t udp_timeout;
		uint32_t icmp_timeout;
		uint32_t conversation_check_interval_ms;

		/**
		 * Conversation reconstruction
		 */
		unsigned int time_window_size_ms;	// Size of window in miliseconds
		unsigned int count_window_size;

		/**
		 * Output
		 */
		bool print_extra_features;			// IPs, ports, end timestamp
		bool print_filename;

	public:
		Config();
		~Config();

		int get_files_count() const;
		void set_files_count(int files_c);

		char **get_files_values() const;
		void set_files_values(char **files_v);
		
		int get_interface_num() const;
		void set_interface_num(int interface_num);

		int get_pcap_read_timeout() const;
		void set_pcap_read_timeout(int pcap_read_timeout);

		size_t get_additional_frame_len() const;
		void set_additional_frame_len(size_t additional_frame_len);

		uint32_t get_ipfrag_timeout() const;
		void set_ipfrag_timeout(uint32_t ipfrag);

		uint32_t get_ipfrag_check_interval_ms() const;
		void set_ipfrag_check_interval_ms(uint32_t ipfrag_check_interval_ms);

		uint32_t get_tcp_syn_timeout() const;
		void set_tcp_syn_timeout(uint32_t tcp_syn);

		uint32_t get_tcp_estab_timeout() const;
		void set_tcp_estab_timeout(uint32_t tcp_estab);

		uint32_t get_tcp_rst_timeout() const;
		void set_tcp_rst_timeout(uint32_t tcp_rst);

		uint32_t get_tcp_fin_timeout() const;
		void set_tcp_fin_timeout(uint32_t tcp_fin);

		uint32_t get_tcp_last_ack_timeout() const;
		void set_tcp_last_ack_timeout(uint32_t tcp_last_ack);

		uint32_t get_udp_timeout() const;
		void set_udp_timeout(uint32_t udp);

		uint32_t get_icmp_timeout() const;
		void set_icmp_timeout(uint32_t icmp);

		uint32_t get_conversation_check_interval_ms() const;
		void set_conversation_check_interval_ms(uint32_t conversation_check_interval_ms);

		unsigned int get_time_window_size_ms() const;
		void set_time_window_size_ms(unsigned int time_window_size_ms);

		unsigned int get_count_window_size() const;
		void set_count_window_size(unsigned int count_window_size);

		bool should_print_extra_features() const;
		void set_print_extra_features(bool print_extra_features);

		bool should_print_filename() const;
		void set_print_filename(bool print_filename);
	};
}
