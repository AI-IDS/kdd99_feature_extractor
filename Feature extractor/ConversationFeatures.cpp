#include "ConversationFeatures.h"


namespace FeatureExtractor {
	ConversationFeatures::ConversationFeatures(Conversation *conv)
		: conv(conv)
	{
	}


	ConversationFeatures::~ConversationFeatures()
	{
	}


	/**
	 * Getters, setters, inc & dec for derived feature values
	 */
	inline uint32_t ConversationFeatures::get_count() const {
		return count;
	}
	inline void ConversationFeatures::set_count(uint32_t count) {
		this->count = count;
	}
	inline void ConversationFeatures::inc_count() {
		count++;
	}
	inline void ConversationFeatures::dec_count() {
		count--;
	}

	inline uint32_t ConversationFeatures::get_srv_count() const {
		return srv_count;
	}
	inline void ConversationFeatures::set_srv_count(uint32_t srv_count) {
		this->srv_count = srv_count;
	}
	inline void ConversationFeatures::inc_srv_count(){
		srv_count++;
	}
	inline void ConversationFeatures::dec_srv_count() {
		srv_count--;
	}

	inline double ConversationFeatures::get_serror_rate() const {
		return serror_rate;
	}
	inline void ConversationFeatures::set_serror_rate(double serror_rate) {
		this->serror_rate = serror_rate;
	}

	inline double ConversationFeatures::get_srv_serror_rate() const {
		return srv_serror_rate;
	}
	inline void ConversationFeatures::set_srv_serror_rate(double srv_serror_rate) {
		this->srv_serror_rate = srv_serror_rate;
	}

	inline double ConversationFeatures::get_rerror_rate() const {
		return rerror_rate;
	}
	inline void ConversationFeatures::set_rerror_rate(double rerror_rate) {
		this->rerror_rate = rerror_rate;
	}

	inline double ConversationFeatures::get_srv_rerror_rate() const {
		return srv_rerror_rate;
	}
	inline void ConversationFeatures::set_srv_rerror_rate(double srv_rerror_rate) {
		this->srv_rerror_rate = srv_rerror_rate;
	}

	inline double ConversationFeatures::get_same_srv_rate() const {
		return same_srv_rate;
	}
	inline void ConversationFeatures::set_same_srv_rate(double same_srv_rate) {
		this->same_srv_rate = same_srv_rate;
	}

	inline double ConversationFeatures::get_diff_srv_rate() const {
		return diff_srv_rate;
	}
	inline void ConversationFeatures::set_diff_srv_rate(double diff_srv_rate) {
		this->diff_srv_rate = diff_srv_rate;
	}

	inline double ConversationFeatures::get_srv_diff_host_rate() const {
		return srv_diff_host_rate;
	}
	inline void ConversationFeatures::set_srv_diff_host_rate(double srv_diff_host_rate) {
		this->srv_diff_host_rate = srv_diff_host_rate;
	}

	inline uint32_t ConversationFeatures::get_dst_host_count() const {
		return dst_host_count;
	}
	inline void ConversationFeatures::set_dst_host_count(uint32_t dst_host_count) {
		this->dst_host_count = dst_host_count;
	}
	inline void ConversationFeatures::inc_dst_host_count() {
		dst_host_count++;
	}
	inline void ConversationFeatures::dec_dst_host_count() {
		dst_host_count--;
	}

	inline uint32_t ConversationFeatures::get_dst_host_srv_count() const {
		return dst_host_srv_count;
	}
	inline void ConversationFeatures::set_dst_host_srv_count(uint32_t dst_host_srv_count)	{
		this->dst_host_srv_count = dst_host_srv_count;
	}
	inline void ConversationFeatures::inc_dst_host_srv_count() {
		dst_host_srv_count++;
	}
	inline void ConversationFeatures::dec_dst_host_srv_count() {
		dst_host_srv_count--;
	}

	inline double ConversationFeatures::get_dst_host_same_srv_rate() const {
		return dst_host_same_srv_rate;
	}
	inline void ConversationFeatures::set_dst_host_same_srv_rate(double dst_host_same_srv_rate) {
		this->dst_host_same_srv_rate = dst_host_same_srv_rate;
	}

	inline double ConversationFeatures::get_dst_host_diff_srv_rate() const {
		return dst_host_diff_srv_rate;
	}
	inline void ConversationFeatures::set_dst_host_diff_srv_rate(double dst_host_diff_srv_rate) {
		this->dst_host_diff_srv_rate = dst_host_diff_srv_rate;
	}

	inline double ConversationFeatures::get_dst_host_same_src_port_rate() const {
		return dst_host_same_src_port_rate;
	}
	inline void ConversationFeatures::set_dst_host_same_src_port_rate(double dst_host_same_src_port_rate) {
		this->dst_host_same_src_port_rate = dst_host_same_src_port_rate;
	}

	inline double ConversationFeatures::get_dst_host_srv_diff_host_rate() const {
		return dst_host_srv_diff_host_rate;
	}
	inline void ConversationFeatures::set_dst_host_srv_diff_host_rate(double dst_host_srv_diff_host_rate) {
		this->dst_host_srv_diff_host_rate = dst_host_srv_diff_host_rate;
	}

	inline double ConversationFeatures::get_dst_host_serror_rate() const {
		return dst_host_serror_rate;
	}
	inline void ConversationFeatures::set_dst_host_serror_rate(double dst_host_serror_rate) {
		this->dst_host_serror_rate = dst_host_serror_rate;
	}

	inline double ConversationFeatures::get_dst_host_srv_serror_rate() const {
		return dst_host_srv_serror_rate;
	}
	inline void ConversationFeatures::set_dst_host_srv_serror_rate(double dst_host_srv_serror_rate) {
		this->dst_host_srv_serror_rate = dst_host_srv_serror_rate;
	}

	inline double ConversationFeatures::get_dst_host_rerror_rate() const {
		return dst_host_rerror_rate;
	}
	inline void ConversationFeatures::set_dst_host_rerror_rate(double dst_host_rerror_rate) {
		this->dst_host_rerror_rate = dst_host_rerror_rate;
	}

	inline double ConversationFeatures::get_dst_host_srv_rerror_rate() const {
		return dst_host_srv_rerror_rate;
	}
	inline void ConversationFeatures::set_dst_host_srv_rerror_rate(double dst_host_srv_rerror_rate) {
		this->dst_host_srv_rerror_rate = dst_host_srv_rerror_rate;
	}

}
