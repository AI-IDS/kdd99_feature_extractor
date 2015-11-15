#include "ConversationFeatures.h"


namespace FeatureExtractor {
	ConversationFeatures::ConversationFeatures(Conversation *conv)
		: conv(conv)
	{
		conv->register_reference();
	}


	ConversationFeatures::~ConversationFeatures()
	{
		// Conversation object commits suicide when nobody needs it anymore
		conv->deregister_reference();
	}


	Conversation *ConversationFeatures::get_conversation()
	{
		return conv;
	}

	/**
	 * Getters, setters, inc & dec for derived feature values
	 */
	uint32_t ConversationFeatures::get_count() const {
		return count;
	}
	void ConversationFeatures::set_count(uint32_t count) {
		this->count = count;
	}

	uint32_t ConversationFeatures::get_srv_count() const {
		return srv_count;
	}
	void ConversationFeatures::set_srv_count(uint32_t srv_count) {
		this->srv_count = srv_count;
	}

	double ConversationFeatures::get_serror_rate() const {
		return serror_rate;
	}
	void ConversationFeatures::set_serror_rate(double serror_rate) {
		this->serror_rate = serror_rate;
	}

	double ConversationFeatures::get_srv_serror_rate() const {
		return srv_serror_rate;
	}
	void ConversationFeatures::set_srv_serror_rate(double srv_serror_rate) {
		this->srv_serror_rate = srv_serror_rate;
	}

	double ConversationFeatures::get_rerror_rate() const {
		return rerror_rate;
	}
	void ConversationFeatures::set_rerror_rate(double rerror_rate) {
		this->rerror_rate = rerror_rate;
	}

	double ConversationFeatures::get_srv_rerror_rate() const {
		return srv_rerror_rate;
	}
	void ConversationFeatures::set_srv_rerror_rate(double srv_rerror_rate) {
		this->srv_rerror_rate = srv_rerror_rate;
	}

	double ConversationFeatures::get_same_srv_rate() const {
		return same_srv_rate;
	}
	void ConversationFeatures::set_same_srv_rate(double same_srv_rate) {
		this->same_srv_rate = same_srv_rate;
	}

	double ConversationFeatures::get_diff_srv_rate() const {
		return diff_srv_rate;
	}
	void ConversationFeatures::set_diff_srv_rate(double diff_srv_rate) {
		this->diff_srv_rate = diff_srv_rate;
	}

	double ConversationFeatures::get_srv_diff_host_rate() const {
		return (srv_count == 0) ? 0.0 : ((srv_count - same_srv_count) / (double)srv_count);
	}

	uint32_t ConversationFeatures::get_same_srv_count() const {
		return same_srv_count;
	}
	void ConversationFeatures::set_same_srv_count(uint32_t same_srv_count) {
		this->same_srv_count = same_srv_count;
	}

	uint32_t ConversationFeatures::get_dst_host_count() const {
		return dst_host_count;
	}
	void ConversationFeatures::set_dst_host_count(uint32_t dst_host_count) {
		this->dst_host_count = dst_host_count;
	}

	uint32_t ConversationFeatures::get_dst_host_srv_count() const {
		return dst_host_srv_count;
	}
	void ConversationFeatures::set_dst_host_srv_count(uint32_t dst_host_srv_count)	{
		this->dst_host_srv_count = dst_host_srv_count;
	}

	double ConversationFeatures::get_dst_host_same_srv_rate() const {
		return dst_host_same_srv_rate;
	}
	void ConversationFeatures::set_dst_host_same_srv_rate(double dst_host_same_srv_rate) {
		this->dst_host_same_srv_rate = dst_host_same_srv_rate;
	}

	double ConversationFeatures::get_dst_host_diff_srv_rate() const {
		return dst_host_diff_srv_rate;
	}
	void ConversationFeatures::set_dst_host_diff_srv_rate(double dst_host_diff_srv_rate) {
		this->dst_host_diff_srv_rate = dst_host_diff_srv_rate;
	}

	double ConversationFeatures::get_dst_host_same_src_port_rate() const {
		return dst_host_same_src_port_rate;
	}
	void ConversationFeatures::set_dst_host_same_src_port_rate(double dst_host_same_src_port_rate) {
		this->dst_host_same_src_port_rate = dst_host_same_src_port_rate;
	}

	double ConversationFeatures::get_dst_host_serror_rate() const {
		return dst_host_serror_rate;
	}
	void ConversationFeatures::set_dst_host_serror_rate(double dst_host_serror_rate) {
		this->dst_host_serror_rate = dst_host_serror_rate;
	}

	double ConversationFeatures::get_dst_host_srv_serror_rate() const {
		return dst_host_srv_serror_rate;
	}
	void ConversationFeatures::set_dst_host_srv_serror_rate(double dst_host_srv_serror_rate) {
		this->dst_host_srv_serror_rate = dst_host_srv_serror_rate;
	}

	double ConversationFeatures::get_dst_host_rerror_rate() const {
		return dst_host_rerror_rate;
	}
	void ConversationFeatures::set_dst_host_rerror_rate(double dst_host_rerror_rate) {
		this->dst_host_rerror_rate = dst_host_rerror_rate;
	}

	double ConversationFeatures::get_dst_host_srv_rerror_rate() const {
		return dst_host_srv_rerror_rate;
	}
	void ConversationFeatures::set_dst_host_srv_rerror_rate(double dst_host_srv_rerror_rate) {
		this->dst_host_srv_rerror_rate = dst_host_srv_rerror_rate;
	}

	double ConversationFeatures::get_dst_host_srv_diff_host_rate() const {
		return (dst_host_srv_count == 0) ? 0.0 : ((dst_host_srv_count - dst_host_same_srv_count) / (double)dst_host_srv_count);
	}

	uint32_t ConversationFeatures::get_dst_host_same_srv_count() const {
		return dst_host_same_srv_count;
	}
	void ConversationFeatures::set_dst_host_same_srv_count(uint32_t dst_host_same_srv_count) {
		this->dst_host_same_srv_count = dst_host_same_srv_count;
	}

}
