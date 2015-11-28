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
		assert(!this->is_empty() && "Attempt to insert fragment to reassembled datagram");

		Hole *prev = nullptr;
		Hole *hole = this->first_hole;
		while (hole) { // 7. + 1. Loop finished when no next hole descriptor

			// 1.-3. Find hole that fragment fits
			while (hole && (frag_start > hole->end || frag_end < hole->start)) {

				// Part of 6. If last fragment change update last hole end (initiated to infinity)
				if (is_last_frag && !hole->next) {
					hole->end = frag_end;

					// If hole makes no sense, destroy it
					if (hole->start > hole->end) {
						if (prev)
							prev->next = hole->next;
						else
							first_hole = hole->next;
						delete hole;
						hole = nullptr;
						break;
					}
				}

				// 1. Select the next hole  descriptor  from  the  hole  descriptor list.
				prev = hole;
				hole = hole->next;
			} // End of 1.-3. Find hole...

			if (hole) {
				Hole *next = hole->next;

				// 5. New hole before fragment
				if (frag_start > hole->start) {
					Hole *new_hole = new Hole(hole->start, frag_end - 1, next);
					if (prev)
						prev->next = new_hole;
					else
						first_hole = new_hole;
					prev = new_hole;
				}

				// 6. New hole after fragment 
				// If last fragment change update last hole end (initiated to infinity)
				if (is_last_frag && !next) {
					hole->end = frag_end;
				}
				if (frag_end < hole->end) {
					Hole *new_hole = new Hole(frag_end + 1, hole->end, next);
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

				// If no hole except the one to be deleted, the list is empty now
				if (!prev && !next)
					first_hole = nullptr;
			}
		}

		// 8: If the hole descriptor list is now empty, the datagram is now complete
		if (this->is_empty()) {
			//TODO: got the datagram bitch!
		}
	}
}