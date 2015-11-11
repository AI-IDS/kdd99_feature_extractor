#include "TimeoutValues.h"


namespace FeatureExtractor {
	/**
	 * Constructor for default timeout values:
	 * - IP Fragmentation timeout 30s (Linux default)
	 *		http://www.linuxinsight.com/proc_sys_net_ipv4_ipfrag_time.html
	 * - Other values derived from iptables doc
	 *		http://www.iptables.info/en/connection-state.html
	 */
	TimeoutValues::TimeoutValues()
		: ipfrag(30)
		, ipfrag_check_interval(1)
		, tcp_syn(120)
		, tcp_estab(5 * 24 * 3600) // 5 days
		, tcp_rst(10)
		, tcp_fin(120)
		, tcp_last_ack(30)
		, udp(180)
		, icmp(30)
		, conversation_check_interval(1)
	{
	}


	TimeoutValues::~TimeoutValues()
	{
	}

	inline uint32_t TimeoutValues::get_ipfrag() const
	{
		return ipfrag;
	}
	inline void TimeoutValues::set_ipfrag(uint32_t ipfrag)
	{
		this->ipfrag = ipfrag;
	}

	inline uint32_t TimeoutValues::get_ipfrag_check_interval() const
	{
		return ipfrag_check_interval;
	}
	inline void TimeoutValues::set_ipfrag_check_interval(uint32_t ipfrag_check_interval)
	{
		this->ipfrag_check_interval = ipfrag_check_interval;
	}

	inline uint32_t TimeoutValues::get_tcp_syn() const
	{
		return tcp_syn;
	}
	inline void TimeoutValues::set_tcp_syn(uint32_t tcp_syn)
	{
		this->tcp_syn = tcp_syn;
	}

	inline uint32_t TimeoutValues::get_tcp_estab() const
	{
		return tcp_estab;
	}
	inline void TimeoutValues::set_tcp_estab(uint32_t tcp_estab)
	{
		this->tcp_estab = tcp_estab;
	}

	inline uint32_t TimeoutValues::get_tcp_rst() const
	{
		return tcp_rst;
	}
	inline void TimeoutValues::set_tcp_rst(uint32_t tcp_rst)
	{
		this->tcp_rst = tcp_rst;
	}

	inline uint32_t TimeoutValues::get_tcp_fin() const
	{
		return tcp_fin;
	}
	inline void TimeoutValues::set_tcp_fin(uint32_t tcp_fin)
	{
		this->tcp_fin = tcp_fin;
	}

	inline uint32_t TimeoutValues::get_tcp_last_ack() const
	{
		return tcp_last_ack;
	}
	inline void TimeoutValues::set_tcp_last_ack(uint32_t tcp_last_ack)
	{
		this->tcp_last_ack = tcp_last_ack;
	}

	inline uint32_t TimeoutValues::get_udp() const
	{
		return udp;
	}
	inline void TimeoutValues::set_udp(uint32_t udp)
	{
		this->udp = udp;
	}

	inline uint32_t TimeoutValues::get_icmp() const
	{
		return icmp;
	}
	inline void TimeoutValues::set_icmp(uint32_t icmp)
	{
		this->icmp = icmp;
	}

	inline uint32_t TimeoutValues::get_conversation_check_interval() const
	{
		return conversation_check_interval;
	}
	inline void TimeoutValues::set_conversation_check_interval(uint32_t conversation_check_interval)
	{
		this->conversation_check_interval = conversation_check_interval;
	}

}
