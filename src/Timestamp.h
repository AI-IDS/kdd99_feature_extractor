#pragma once

#include "types.h"
// Bug in win WpdPack_4_1_2: On line 69 of pcap-stdinc.h, 'inline' is re-defined
// http://www.winpcap.org/pipermail/winpcap-bugs/2013-November/001760.html
// Solved by including pcap.h after standard libs
#include <pcap.h>

namespace FeatureExtractor {
	/**
	 * Wrapper class for timeval with aditional operations
	 */
	class Timestamp
	{
		struct timeval ts;

	public:
		Timestamp();
		Timestamp(const struct timeval &ts);
		Timestamp(int64_t usecs);
		~Timestamp();

		struct timeval get_timeval() const;
		int64_t get_secs() const;
		int64_t get_usecs() const;
		int64_t get_total_usecs() const;
		int64_t get_total_msecs() const;

		bool operator==(const Timestamp &b) const;
		bool operator!=(const Timestamp &b) const;
		bool operator<(const Timestamp &b) const;
		bool operator>(const Timestamp &b) const;
		bool operator<=(const Timestamp &b) const;
		bool operator>=(const Timestamp &b) const;
		Timestamp operator+(const Timestamp &b) const;
		Timestamp operator-(const Timestamp &b) const;
		Timestamp operator+(int64_t b) const;	// Add usecs
		Timestamp operator-(int64_t b) const;	// Substract usecs
	};
}

