#include "IpReassemblyBufferHoleList.h"
#include <limits.h>
#include <assert.h>

namespace FeatureExtractor {
	IpReassemblyBufferHoleList::Hole::Hole() 
		: start(0), end(SIZE_MAX), next(nullptr)
	{}

	IpReassemblyBufferHoleList::Hole::Hole(size_t start, size_t end, Hole *next)
	{
		this->start = start;
		this->end = end;
		this->next = next;
	}

	IpReassemblyBufferHoleList::IpReassemblyBufferHoleList() 
		: first_hole(new Hole())
	{}

	IpReassemblyBufferHoleList::~IpReassemblyBufferHoleList()
	{
		// Deallocate linked list of holes
		Hole *next;
		while (first_hole) {
			next = first_hole->next;
			delete first_hole;
			first_hole = next;
		}
	}

	bool IpReassemblyBufferHoleList::is_empty() const
	{
		return (first_hole == nullptr);
	}

	/*
	 * RFC 815 - section 3: Fragment Processing Algorithm
	 * Terms start (end) in code bellow corresponds to first (last) in RFC. 
	 */
	void IpReassemblyBufferHoleList::add_fragment(size_t frag_start, size_t frag_end, bool is_last_frag) {
		// Should not insert to completed datagram
		assert(!this->is_empty());

		Hole *prev = nullptr;
		Hole *hole = this->first_hole;
		while (hole) { // 7. + 1. Loop finished when no next hole descriptor

			// 1.-3. Find hole that fragment fits
			while (hole && (frag_start > hole->end || frag_end < hole->start)) {
				prev = hole;
				hole = hole->next;
			}

			if (hole) {
				Hole *next = hole->next;

				// 5. New hole before fragment
				if (frag_start > hole->start) {
					Hole *new_hole = new Hole(hole->start, frag_end - 1, hole->next);
					if (prev)
						prev->next = new_hole;
					else
						first_hole = new_hole;
					prev = new_hole;
				}

				// 6. New hole after fragment
				if (frag_end < hole->end && !is_last_frag) {
					Hole *new_hole = new Hole(frag_end + 1, hole->end, hole->next);
					if (prev)
						prev->next = new_hole;
					else
						first_hole = new_hole;
					prev = new_hole;
				}

				// 4. Delete hole descriptor
				delete hole;

				// 1. Select the next hole  descriptor
				hole = next;
			}
		}

		// 8: If the hole descriptor list is now empty, the datagram is now complete
		if (this->is_empty()) {
			//TODO: got the IP bitch!
		}
	}
}