#pragma once
#include "StatsWindow.h"

namespace FeatureExtractor {
	class StatsWindowCount : public StatsWindow
	{
	public:
		StatsWindowCount();
		~StatsWindowCount();


		/**
		* Method performing window maintenance.
		*
		* Keeps the size of queue <= 100. Each time new conversation is added, the 
		* oldest one is removed from windows.
		*/
		virtual void perform_window_maintenance(Conversation *new_conv) = 0;
	};
}
