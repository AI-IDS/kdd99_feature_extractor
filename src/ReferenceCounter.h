#pragma once

namespace FeatureExtractor {
	/*
	 * General implementation of reference counting
	 *
	 * Every instance can keep the number of references(pointers) to itself.If the this number
	 * reaches zero after deregistering a reference, the object commits suicide(delete this).
	 */
	class ReferenceCounter
	{
		// Number of references (pointers) to this instance
		int reference_count;

	public:
		ReferenceCounter();

		/**
		* Increment the number of references to this object
		*/
		void register_reference();

		/**
		* Decrement the number of references to this object
		* If the number of references reaches 0, commit suicide (delete this).
		*
		* The calling object/function should not use reference to this object
		* after calling this method.
		*/
		void deregister_reference();
	};
}
