#pragma once

#include <stdint.h>
#include "Conversation.h"

namespace FeatureExtractor {

	/**
	 * Set of features with link to conversation
	 */
	class ConversationFeatures
	{
		// Derived features are extracted directly from conversation object
		const Conversation *conv;

		/**
		 * Derived features for 2s time window
		 */
		uint32_t count;
		uint32_t srv_count;
		double serror_rate;
		double srv_serror_rate;
		double rerror_rate;
		double srv_rerror_rate;
		double same_srv_rate;
		double diff_srv_rate;
		double srv_diff_host_rate;

		/**
		* Derived features for 100 connection window
		*/
		uint32_t dst_host_count;
		uint32_t dst_host_srv_count;
		double dst_host_same_srv_rate;
		double dst_host_diff_srv_rate;
		double dst_host_same_src_port_rate;
		double dst_host_srv_diff_host_rate;
		double dst_host_serror_rate;
		double dst_host_srv_serror_rate;
		double dst_host_rerror_rate;
		double dst_host_srv_rerror_rate;

	public:
		ConversationFeatures(Conversation *);
		~ConversationFeatures();

		uint32_t get_count() const;
		void set_count(uint32_t count);
		void inc_count();
		void dec_count();

		uint32_t get_srv_count() const;
		void set_srv_count(uint32_t srv_count);
		void inc_srv_count();
		void dec_srv_count();

		double get_serror_rate() const;
		void set_serror_rate(double serror_rate);

		double get_srv_serror_rate() const;
		void set_srv_serror_rate(double srv_serror_rate);

		double get_rerror_rate() const;
		void set_rerror_rate(double rerror_rate);

		double get_srv_rerror_rate() const;
		void set_srv_rerror_rate(double srv_rerror_rate);

		double get_same_srv_rate() const;
		void set_same_srv_rate(double same_srv_rate);

		double get_diff_srv_rate() const;
		void set_diff_srv_rate(double diff_srv_rate);

		double get_srv_diff_host_rate() const;
		void set_srv_diff_host_rate(double srv_diff_host_rate);

		uint32_t get_dst_host_count() const;
		void set_dst_host_count(uint32_t dst_host_count);
		void inc_dst_host_count();
		void dec_dst_host_count();

		uint32_t get_dst_host_srv_count() const;
		void set_dst_host_srv_count(uint32_t dst_host_srv_count);
		void inc_dst_host_srv_count();
		void dec_dst_host_srv_count();

		double get_dst_host_same_srv_rate() const;
		void set_dst_host_same_srv_rate(double dst_host_same_srv_rate);

		double get_dst_host_diff_srv_rate() const;
		void set_dst_host_diff_srv_rate(double dst_host_diff_srv_rate);

		double get_dst_host_same_src_port_rate() const;
		void set_dst_host_same_src_port_rate(double dst_host_same_src_port_rate);

		double get_dst_host_srv_diff_host_rate() const;
		void set_dst_host_srv_diff_host_rate(double dst_host_srv_diff_host_rate);

		double get_dst_host_serror_rate() const;
		void set_dst_host_serror_rate(double dst_host_serror_rate);

		double get_dst_host_srv_serror_rate() const;
		void set_dst_host_srv_serror_rate(double dst_host_srv_serror_rate);

		double get_dst_host_rerror_rate() const;
		void set_dst_host_rerror_rate(double dst_host_rerror_rate);

		double get_dst_host_srv_rerror_rate() const;
		void set_dst_host_srv_rerror_rate(double dst_host_srv_rerror_rate);


	};
}
