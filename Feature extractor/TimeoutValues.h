#pragma once

#include <stdint.h>

namespace FeatureExtractor {

	/**
	 * Class to store timeout settings (all values are meant to be in seconds)
	 */
	class TimeoutValues
	{
		uint32_t ipfrag;
		uint32_t ipfrag_check_interval;

		uint32_t tcp_syn;
		uint32_t tcp_estab;
		uint32_t tcp_rst;
		uint32_t tcp_fin;
		uint32_t tcp_last_ack;
		uint32_t udp;
		uint32_t icmp;
		uint32_t conversation_check_interval;

	public:
		TimeoutValues();
		~TimeoutValues();

		uint32_t get_ipfrag() const;
		void set_ipfrag(uint32_t ipfrag);

		uint32_t get_ipfrag_check_interval() const;
		void set_ipfrag_check_interval(uint32_t ipfrag_check_interval);

		uint32_t get_tcp_syn() const;
		void set_tcp_syn(uint32_t tcp_syn);

		uint32_t get_tcp_estab() const;
		void set_tcp_estab(uint32_t tcp_estab);

		uint32_t get_tcp_rst() const;
		void set_tcp_rst(uint32_t tcp_rst);

		uint32_t get_tcp_fin() const;
		void set_tcp_fin(uint32_t tcp_fin);

		uint32_t get_tcp_last_ack() const;
		void set_tcp_last_ack(uint32_t tcp_last_ack);

		uint32_t get_udp() const;
		void set_udp(uint32_t udp);

		uint32_t get_icmp() const;
		void set_icmp(uint32_t icmp);

		uint32_t get_conversation_check_interval() const;
		void set_conversation_check_interval(uint32_t conversation_check_interval);

	};
}
