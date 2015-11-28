#pragma once

#include "ConversationFeatures.h"

namespace FeatureExtractor {
	/**
	 * Interface for updating features. There are 2 subclasses for updating 
	 * either time or count window statistics.
	 */
	class FeatureUpdater
	{
	public:
		virtual void set_count(ConversationFeatures * f, uint32_t count) = 0;
		virtual void set_srv_count(ConversationFeatures * f, uint32_t srv_count) = 0;
		virtual void set_serror_rate(ConversationFeatures * f, double serror_rate) = 0;
		virtual void set_srv_serror_rate(ConversationFeatures * f, double srv_serror_rate) = 0;
		virtual void set_rerror_rate(ConversationFeatures * f, double rerror_rate) = 0;
		virtual void set_srv_rerror_rate(ConversationFeatures * f, double srv_rerror_rate) = 0;
		virtual void set_same_srv_rate(ConversationFeatures * f, double same_srv_rate) = 0;
		virtual void set_diff_srv_rate(ConversationFeatures * f, double diff_srv_rate) = 0;
		virtual void set_dst_host_same_src_port_rate(ConversationFeatures * f, double dst_host_same_src_port_rate) = 0;
		virtual void set_same_srv_count(ConversationFeatures * f, uint32_t same_srv_count) = 0;
	};
}