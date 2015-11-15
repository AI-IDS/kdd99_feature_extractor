#include "FeatureUpdaterTime.h"


namespace FeatureExtractor {
	void FeatureUpdaterTime::set_count(ConversationFeatures * f, uint32_t count) {
		f->set_count(count);
	}

	void FeatureUpdaterTime::set_srv_count(ConversationFeatures * f, uint32_t srv_count) {
		f->set_srv_count(srv_count);
	}

	void FeatureUpdaterTime::set_serror_rate(ConversationFeatures * f, double serror_rate) {
		f->set_serror_rate(serror_rate);
	}

	void FeatureUpdaterTime::set_srv_serror_rate(ConversationFeatures * f, double srv_serror_rate) {
		f->set_srv_serror_rate(srv_serror_rate);
	}

	void FeatureUpdaterTime::set_rerror_rate(ConversationFeatures * f, double rerror_rate) {
		f->set_rerror_rate(rerror_rate);
	}

	void FeatureUpdaterTime::set_srv_rerror_rate(ConversationFeatures * f, double srv_rerror_rate) {
		f->set_srv_rerror_rate(srv_rerror_rate);
	}

	void FeatureUpdaterTime::set_same_srv_rate(ConversationFeatures * f, double same_srv_rate) {
		f->set_same_srv_rate(same_srv_rate);
	}

	void FeatureUpdaterTime::set_diff_srv_rate(ConversationFeatures * f, double diff_srv_rate) {
		f->set_diff_srv_rate(diff_srv_rate);
	}

	void FeatureUpdaterTime::set_dst_host_same_src_port_rate(ConversationFeatures * f, double dst_host_same_src_port_rate) {
		// Do nothing - no such feature for time window
	}

	void FeatureUpdaterTime::set_same_srv_count(ConversationFeatures * f, uint32_t same_srv_count) {
		f->set_same_srv_count(same_srv_count);
	}

}
