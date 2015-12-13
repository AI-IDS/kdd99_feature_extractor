#include <sstream>
#include <iostream>
#include <iomanip>
#include "ConversationFeatures.h"


namespace FeatureExtractor {
	using namespace std;

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

	// Allow using localtime instead of localtime_s 
	#pragma warning(disable : 4996)
	void ConversationFeatures::print(bool print_extra_features) const
	{
		stringstream ss;

		// Intrinsic features
		ss << noshowpoint << setprecision(0) << (conv->get_duration_ms() / 1000) << ','; // Cut fractional part
		ss << conv->get_protocol_type_str() << ',';
		ss << conv->get_service_str() << ',';
		ss << conv->get_state_str() << ',';
		ss << conv->get_src_bytes() << ',';
		ss << conv->get_dst_bytes() << ',';
		ss << conv->land() << ',';
		ss << conv->get_wrong_fragments() << ',';
		ss << conv->get_urgent_packets() << ',';

		// Derived time windows features
		ss << fixed << showpoint <<setprecision(2);
		ss << count << ',';
		ss << srv_count << ',';
		ss << serror_rate << ',';
		ss << srv_serror_rate << ',';
		ss << rerror_rate << ',';
		ss << srv_rerror_rate << ',';
		ss << same_srv_rate << ',';
		ss << diff_srv_rate << ',';
		ss << get_srv_diff_host_rate() << ',';

		// Derived connection count window features
		ss << dst_host_count << ',';
		ss << dst_host_srv_count << ',';
		ss << dst_host_same_srv_rate << ',';
		ss << dst_host_diff_srv_rate << ',';
		ss << dst_host_same_src_port_rate << ',';
		ss << get_dst_host_srv_diff_host_rate() << ',';
		ss << dst_host_serror_rate << ',';
		ss << dst_host_srv_serror_rate << ',';
		ss << dst_host_rerror_rate << ',';
		ss << dst_host_srv_rerror_rate;

		if (print_extra_features) {
			const FiveTuple *ft = conv->get_five_tuple_ptr();

			// TODO: ugly wtf, but working
			uint32_t src_ip = ft->get_src_ip();
			uint32_t dst_ip = ft->get_dst_ip();
			uint8_t *sip = (uint8_t *)&src_ip;
			uint8_t *dip = (uint8_t *)&dst_ip;
			ss << ',';
			ss << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3] << ',';
			ss << ft->get_src_port() << ',';
			ss << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3] << ',';
			ss << ft->get_dst_port() << ',';

			// Time (e.g.: 2010-06-14T00:11:23)
			struct tm *ltime;
			//struct tm timeinfo;
			char timestr[20];
			time_t local_tv_sec;
			local_tv_sec = conv->get_last_ts().get_secs();
			ltime = localtime(&local_tv_sec);
			//localtime_s(&timeinfo, &local_tv_sec);
			strftime(timestr, sizeof timestr, "%Y-%m-%dT%H:%M:%S", ltime);
			//strftime(timestr, sizeof timestr, "%Y-%m-%dT%H:%M:%S", &timeinfo);
			ss << timestr;
		}

		cout << ss.str() << endl;
	}
	

	void ConversationFeatures::print_human() const
	{
		conv->print_human();

		stringstream ss;
		ss << fixed << setprecision(2);
		ss << "count = " << count << endl;
		ss << "srv_count = " << srv_count << endl;
		ss << "serror_rate = " << serror_rate << endl;
		ss << "srv_serror_rate = " << srv_serror_rate << endl;
		ss << "rerror_rate = " << rerror_rate << endl;
		ss << "srv_rerror_rate = " << srv_rerror_rate << endl;
		ss << "same_srv_rate = " << same_srv_rate << endl;
		ss << "diff_srv_rate = " << diff_srv_rate << endl;
		ss << "get_srv_diff_host_rate = " << get_srv_diff_host_rate() << endl;
		ss << "dst_host_count = " << dst_host_count << endl;
		ss << "dst_host_srv_count = " << dst_host_srv_count << endl;
		ss << "dst_host_same_srv_rate = " << dst_host_same_srv_rate << endl;
		ss << "dst_host_diff_srv_rate = " << dst_host_diff_srv_rate << endl;
		ss << "dst_host_same_src_port_rate = " << dst_host_same_src_port_rate << endl;
		ss << "get_dst_host_srv_diff_host_rate = " << get_dst_host_srv_diff_host_rate() << endl;
		ss << "dst_host_serror_rate = " << dst_host_serror_rate << endl;
		ss << "dst_host_srv_serror_rate = " << dst_host_srv_serror_rate << endl;
		ss << "dst_host_rerror_rate = " << dst_host_rerror_rate << endl;
		ss << "dst_host_srv_rerror_rate = " << dst_host_srv_rerror_rate << endl;
		cout << ss.str() << endl;
	}

}
