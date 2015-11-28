#include "ReferenceCounter.h"
#include <assert.h>


namespace FeatureExtractor {
	ReferenceCounter::ReferenceCounter()
		: reference_count(0)
	{
	}


	void ReferenceCounter::register_reference()
	{
		reference_count++;
	}

	void ReferenceCounter::deregister_reference()
	{
		assert(reference_count > 0  && "Deregistering reference failed: no more registered references left!");

		// If no more references, commit suicide (hahaha)
		if (!(reference_count--))
			delete this;
	}
}
