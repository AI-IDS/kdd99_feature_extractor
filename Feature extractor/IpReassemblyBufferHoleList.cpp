#include "IpReassemblyBufferHoleList.h"
#include <limits.h>
#include <stddef.h>
#include <assert.h>

namespace FeatureExtractor {
	IpReassemblyBufferHoleList::Hole::Hole() : start(0), end(SIZE_MAX), next(NULL)
	{}

	IpReassemblyBufferHoleList::Hole::Hole(size_t start, size_t end, Hole *next)
	{
		this->start = start;
		this->end = end;
		this->next = next;
	}


	IpReassemblyBufferHoleList::IpReassemblyBufferHoleList() : datagram_size(0)
	{
		this->first_hole = new Hole();
	}


	IpReassemblyBufferHoleList::~IpReassemblyBufferHoleList()
	{
	}

	bool IpReassemblyBufferHoleList::is_empty()
	{
		return (first_hole == NULL);
	}

	size_t IpReassemblyBufferHoleList::get_datagram_size() 
	{
		return datagram_size;
	}

	/*
	 * RFC 815 - section 3: Fragment Processing Algorithm
	 */
	void IpReassemblyBufferHoleList::add_fragment(size_t start, size_t end, bool last_fragment) {
		assert(!this->is_empty());

		// Remember the size
		if (end > datagram_size)
			datagram_size = end;

		// 1.-3.: Find hole
		Hole *prev = NULL;
		Hole *hole = this->first_hole;
		while (hole && (start > hole->end || end < hole->start)) {
			prev = hole;
			hole = hole->next;
		}

		if (hole) {
			// 5. New hole before fragment
			if (start > hole->start) {
				Hole *new_hole = new Hole(hole->start, end - 1, hole->next);
				prev->next = new_hole;
				prev = new_hole;
			}

			// 6. New hole after fragment
			if (end < hole->end && !last_fragment) {
				Hole *new_hole = new Hole(end + 1, hole->end, hole->next);
				prev->next = new_hole;
				prev = new_hole;
			}

			// 4. Delete hole descriptor
			delete hole;
		}

		// 8: If the hole descriptor list is now empty, the datagram is now complete
		if (this->is_empty()) {
			//TODO: 
		}
	}
}