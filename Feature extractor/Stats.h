#pragma once

#include "Conversation.h"
#include "ConversationFeatures.h"

namespace FeatureExtractor {
	/**
	 * General interface for statistics about conversations in one window (e.g. timewindow)
	 */
	class Stats
	{
	public:
		virtual ~Stats() { };

		/**
		 * Notify statitics about conversation being removed from window
		 */
		virtual void report_conversation_removal(const Conversation *conv) = 0;

		/**
		 * Notify statitics about new conversation being added to window
		 */
		virtual void report_new_conversation(ConversationFeatures *cf) = 0;
	};
}

