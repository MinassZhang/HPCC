/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* Copyright (c) 2006 Georgia Tech Research Corporation, INRIA
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation;
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef BROADCOM_EGRESS_H
#define BROADCOM_EGRESS_H

#include <queue>
#include "ns3/packet.h"
#include "queue.h"
#include "drop-tail-queue.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/event-id.h"
#include <unordered_map>

namespace ns3 {

	class TraceContainer;

	class BEgressQueue : public Queue {
	public:
		static TypeId GetTypeId(void);
		static const unsigned fCnt = 128; //max number of queues, 128 for NICs
		static const unsigned qCnt = 8; //max number of queues, 8 for switches
		BEgressQueue();
		virtual ~BEgressQueue();
		bool Enqueue(Ptr<Packet> p, uint32_t qIndex);
		bool Enqueue1(Ptr<Packet> p, uint32_t qIndex);//shishi
		Ptr<Packet> DequeueRR(bool paused[]);
		Ptr<Packet> DequeueRR1(bool paused[]);//shishi
		uint32_t GetNBytes(uint32_t qIndex) const;
		uint32_t GetNBytesTotal() const;
		uint32_t GetLastQueue();

		TracedCallback<Ptr<const Packet>, uint32_t> m_traceBeqEnqueue;
		TracedCallback<Ptr<const Packet>, uint32_t> m_traceBeqDequeue;

	private:
		bool DoEnqueue(Ptr<Packet> p, uint32_t qIndex);
		bool DoEnqueue1(Ptr<Packet> p, uint32_t qIndex);//shishi
		Ptr<Packet> DoDequeueRR(bool paused[]);
		Ptr<Packet> DoDequeueRR1(bool paused[]);//shishi
		//for compatibility
		virtual bool DoEnqueue(Ptr<Packet> p);
		virtual bool DoEnqueue1(Ptr<Packet> p);//shishi
		virtual Ptr<Packet> DoDequeue(void);
		virtual Ptr<const Packet> DoPeek(void) const;
		double m_maxBytes; //total bytes limit
		uint32_t m_bytesInQueue[fCnt];
		uint32_t m_bytesInQueueTotal;
		uint32_t m_rrlast;
		uint32_t m_qlast;
		std::vector<Ptr<Queue> > m_queues; // uc queues

		//shishi
		std::unordered_map<uint64_t,uint32_t> pcount;
	};

} // namespace ns3

#endif /* DROPTAIL_H */

