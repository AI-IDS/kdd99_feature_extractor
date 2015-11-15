#pragma once

#include "Conversation.h"
#include "ConversationFeatures.h"

namespace FeatureExtractor {
	/**
	 * General interface for collecting statistics about specific conversations 
	 * (e.g. per host/service in one window)
	 */
	class StatsCollector
	{
	public:
		virtual ~StatsCollector() { };

		/**
		 * Notify statitics about conversation being removed from window
		 */
		virtual void report_conversation_removal(const Conversation *conv) = 0;

		/**
		 * Notify statitics about new conversation being added to window
		 */
		virtual void report_new_conversation(ConversationFeatures *cf) = 0;

		/**
		 * Checks whether the statistical collection is empty (e.g. count == 0)
		 */
		virtual bool is_empty() = 0;
	};
}

