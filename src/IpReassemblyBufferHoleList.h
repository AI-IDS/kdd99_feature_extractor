#pragma once

#include "types.h"

namespace FeatureExtractor {
	class IpReassemblyBufferHoleList
	{
		/*
		 * Hole descriptor in hole descriptor linked list
		 */
		class Hole {
		public:
			size_t start, end;
			Hole *next;
			Hole();
			Hole(size_t first, size_t last, Hole *next);
		};

		// Pointer to linked list
		Hole *first_hole;

	public:
		IpReassemblyBufferHoleList();
		~IpReassemblyBufferHoleList();

		bool is_empty() const;
		void add_fragment(size_t start, size_t end, bool is_last_frag);
	};

}