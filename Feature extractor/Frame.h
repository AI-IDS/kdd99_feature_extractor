#pragma once

#include <stdint.h>

namespace FeatureExtractor {
	///*
	// * Protocol on layer 2
	// */
	//enum L2Protocol : uint8_t;
	//{
	//	ETHERNET2,
	//		OTHER = 0
	//};

	///*
	// * Field Type in Ethernet header
	// */
	//enum L3Protocol : uint16_t
	//{
	//	IP = 0X800,
	//	OTHER = 0
	//};

	///*
	//* Field Protocol in Ethernet header
	//*/
	//enum L4Protocol : uint8_t
	//{
	//	ICMP = 1,
	//	TCP = 9,
	//	UDP = 17,
	//	OTHER
	//};

	class Frame
	{
		//L2Protocol layer2_prot;
		//L3Protocol layer3_prot;
		//L4Protocol layer4_prot;

	public:
		Frame();
		~Frame();
	};

}