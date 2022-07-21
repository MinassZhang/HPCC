#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/pause-header.h"
#include "ns3/flow-id-tag.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "switch-node.h"
#include "qbb-net-device.h"
#include "ppp-header.h"
#include "ns3/int-header.h"
#include <cmath>
#include "murmurhash.h"
#include "ns3/BFCHeader.h"
#include <random>

namespace ns3 {

TypeId SwitchNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SwitchNode")
    .SetParent<Node> ()
    .AddConstructor<SwitchNode> ()
	.AddAttribute("EcnEnabled",
			"Enable ECN marking.",
			BooleanValue(false),
			MakeBooleanAccessor(&SwitchNode::m_ecnEnabled),
			MakeBooleanChecker())
	.AddAttribute("CcMode",
			"CC mode.",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ccMode),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("AckHighPrio",
			"Set high priority for ACK/NACK or not",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ackHighPrio),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("MaxRtt",
			"Max Rtt of the network",
			UintegerValue(9000),
			MakeUintegerAccessor(&SwitchNode::m_maxRtt),
			MakeUintegerChecker<uint32_t>())
  ;
  return tid;
}

SwitchNode::SwitchNode(){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_mmu = CreateObject<SwitchMmu>();
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPktSize[i] = m_lastPktTs[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++) 
		for (uint32_t j = 0; j < qCnt; j++)
			m_txBytes1[i][j] = 0;
	std::string s = std::to_string(m_ecmpSeed);
	char const *name= s.c_str();
    unsigned long seed = AwareHash((unsigned char*)name, strlen(name), 13091204281, 228204732751, 6620830889);
    hash_seed = GenHashSeed(seed);
}

int SwitchNode::GetOutDev(Ptr<const Packet> p, CustomHeader &ch){
	// look up entries
	auto entry = m_rtTable.find(ch.dip);

	// no matching entry
	if (entry == m_rtTable.end())
		return -1;

	// entry found
	auto &nexthops = entry->second;

	// pick one next hop based on hash
	union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = ch.dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	return nexthops[idx];
}

void SwitchNode::CheckAndSendPfc(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldPause(inDev, qIndex)){
		device->SendPfc(qIndex, 0);
		m_mmu->SetPause(inDev, qIndex);
	}
}
void SwitchNode::CheckAndSendResume(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldResume(inDev, qIndex)){
		device->SendPfc(qIndex, 1);
		m_mmu->SetResume(inDev, qIndex);
	}
}

void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){
	// printf("switch: %08x %08x: %u\n",ch.sip,ch.dip,p->GetSize());
	int idx = GetOutDev(p, ch);
	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		//get sip dip
		uint64_t now_time = Simulator::Now().GetTimeStep();
		uint32_t p_size = p->GetSize()- (ch.udp.ih.maxHop-ch.udp.ih.nhop) * 8;
		if((ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)  && p_size < 60)
			p_size = 60;
		uint32_t sip = ch.sip;
		uint32_t dip = ch.dip;
		uint64_t edge = ((uint64_t)sip << 32) | dip;
		//cm->Update(edge,p_size);
		if(m_heap.find(edge) != m_heap.end()) {
			m_heap[edge].first += p_size;
			m_heap[edge].second = now_time;
		}
		else {
			m_heap[edge].first = p_size;
			m_heap[edge].second = now_time;
		}
		uint64_t judgeFlow = m_heap[edge].first;

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			
			if(judgeFlow > 1000000) {
				if(m_flowTable[edge].first == 0)
					qIndex = 4;
				else
					qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg);
			}
			else {
				qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
				++m_flowTable[edge].first;
			}
		}

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();

		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p_size) && m_mmu->CheckEgressAdmission(idx, qIndex, p_size)){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p_size);
				m_mmu->UpdateEgressAdmission(idx, qIndex, p_size);
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);
		}

		auto it = m_heap.begin();
		while( (!m_heap.empty()) && (it != m_heap.end())) {
			if((now_time - m_heap[it->first].second) > 10000) {
				it = m_heap.erase(it);
			}
			else 
				++it;
		}

		m_bytes[inDev][idx][qIndex] += (p_size);
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

uint32_t SwitchNode::AssignQueue(uint32_t port) {
	Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[port]);
	for(uint32_t queue=1;queue<qCnt;queue++) {
		// printf("node,%d,queuerr,%u,%u,%u,%u,%u\n",node_id,queue,q_last,(queue + q_last) % qCnt,egress_bytes[port][(queue + q_last) % qCnt],paused[port][(queue + q_last) % qCnt]);
		uint32_t qindex = (queue + q_last) % qCnt;
		if(m_mmu->egress_bytes[port][qindex] == 0 && qindex != 0 && !dev->GetPause(qindex)) {
			q_last = qindex;
			return qindex;
		}
	}
	std::random_device rd;
	std::default_random_engine e(rd());
	std::uniform_int_distribution<unsigned> u(1,qCnt-1);
	return u(e);
}

void SwitchNode::SendToDev_BFC(Ptr<Packet>p, CustomHeader &ch){
	// printf("switch: %08x %08x: %u\n",ch.sip,ch.dip,p->GetSize());
	int idx = GetOutDev(p, ch);//Egress Port
	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();//Ingress Port

		// determine the qIndex
		uint32_t qIndex;
		uint32_t fid = ch.sip | ch.dip | ch.l3Prot;
		uint32_t hash_fid = MurmurHash2((unsigned char*)(&fid),4,hash_seed);
		uint64_t ekey = (uint64_t)hash_fid | (((uint64_t)idx) << 32);

		uint8_t* buf = p->GetBuffer();
		BFCHeader *bfc = (BFCHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6];
		uint64_t inkey =  (uint64_t)bfc->upstreamQueue | (((uint64_t)inDev) << 32);

		bool reassignQueue = false;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			if(m_flowTable[ekey].first == 0) {
				reassignQueue = true;
			}
			++m_flowTable[ekey].first;//size
			if(reassignQueue) {
				m_flowTable[ekey].second = AssignQueue(idx);//queue seq
			}
			qIndex = m_flowTable[ekey].second;
		}

		uint32_t pkt_size = p->GetSize();
		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, pkt_size) && m_mmu->CheckEgressAdmission(idx, qIndex, pkt_size)){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, pkt_size);
				m_mmu->UpdateEgressAdmission(idx, qIndex, pkt_size);
				printf("%lu,node_revei,%u,%08x,%08x,%u,%u\n",Simulator::Now().GetTimeStep(),m_id,ch.sip,ch.dip,qIndex,ch.udp.seq);
				Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[idx]);
				Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
				uint32_t thre = 2*dev->GetDataRate().GetBitRate() * 1e-6;
				uint32_t Nactive = 0;
				for(int i=0;i<qCnt;i++) {
					if(m_mmu->egress_bytes[idx][i] > 0 && !dev->GetPause(i)){
						++Nactive;
					}
					// printf("%lu,node,%u,%08x,%08x,qindex,%u,bytes,%u,pause,%u,Nactive,%u\n",Simulator::Now().GetTimeStep(),m_id,ch.sip,ch.dip,i,m_mmu->egress_bytes[idx][i],dev->GetPause(i),Nactive);
				}
				// printf("final,%lu,node,%u,%08x,%08x,Nactive,%u\n",Simulator::Now().GetTimeStep(),m_id,ch.sip,ch.dip,Nactive);
				if(m_mmu->egress_bytes[idx][qIndex] * Nactive> thre) {
					printf("%lu,node,%u,%08x,%08x,thre,%u,%u,%u\n",Simulator::Now().GetTimeStep(),m_id,ch.sip,ch.dip,thre,Nactive,m_mmu->egress_bytes[idx][qIndex]);
					bfc->counterIncr=1;
					++m_pauseCount[inkey];
					if(m_pauseCount[inkey] == 1) {
						printf("%lu,node,%u,%08x,%08x,sendPFC,%u,%u,%u,%u,%u\n",Simulator::Now().GetTimeStep(),m_id,ch.sip,ch.dip,m_mmu->egress_bytes[idx][qIndex],Nactive,thre,bfc->upstreamQueue,qIndex);
						device->SendPfc(bfc->upstreamQueue, 0);
						m_mmu->SetPause(inDev, qIndex);
					}
				}
			}else{
				return; // Drop
			}
			// CheckAndSendPfc(inDev, qIndex);
		}
		// bfc->upstreamQueue = qIndex;
		m_bytes[inDev][idx][qIndex] += (pkt_size);
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

void SwitchNode::SendToDev1(Ptr<Packet>p, CustomHeader &ch){
	// printf("switch: %08x %08x: %u\n",ch.sip,ch.dip,p->GetSize());
	int idx = GetOutDev(p, ch);
	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
		}

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();

		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p->GetSize()) && m_mmu->CheckEgressAdmission(idx, qIndex, p->GetSize())){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p->GetSize());
				m_mmu->UpdateEgressAdmission(idx, qIndex, p->GetSize());
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);
		}
		m_bytes[inDev][idx][qIndex] += (p->GetSize());
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

uint32_t SwitchNode::EcmpHash(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t* key_x4 = (const uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h += (h << 2) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

void SwitchNode::SetEcmpSeed(uint32_t seed){
	m_ecmpSeed = seed;
}

void SwitchNode::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void SwitchNode::ClearTable(){
	m_rtTable.clear();
}

// This function can only be called in switch mode
bool SwitchNode::SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch){
	SendToDev_BFC(packet, ch);//SHISHI
	return true;
}

void SwitchNode::SwitchNotifyDequeue_BFC(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
	ch.getInt = 0; // parse INT header
	p->PeekHeader(ch);
	uint32_t fid = ch.sip | ch.dip | ch.l3Prot;
	uint32_t hash_fid = MurmurHash2((unsigned char*)(&fid),4,hash_seed);
	uint64_t ekey = (uint64_t)hash_fid | (((uint64_t)ifIndex) << 32);
	--m_flowTable[ekey].first;

	FlowIdTag t;
	p->PeekPacketTag(t);
	uint32_t inDev = t.GetFlowId();
	uint8_t* buf = p->GetBuffer();
	BFCHeader *bfc = (BFCHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6];
	uint64_t inkey =  (uint64_t)bfc->upstreamQueue | (((uint64_t)inDev) << 32);

	if (qIndex != 0){
		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex,  p->GetSize());
		m_bytes[inDev][ifIndex][qIndex] -=  p->GetSize();
	}
	uint32_t last_upq = bfc->upstreamQueue;
	bfc->upstreamQueue = qIndex;
	if(bfc->counterIncr) {
		bfc->counterIncr = 0;
		--m_pauseCount[inkey];
		if(m_pauseCount[inkey] == 0) {
			Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
			printf("%lu,node,%u,%08x,%08x,setResume,%u,%u\n",Simulator::Now().GetTimeStep(),m_id,ch.sip,ch.dip,qIndex,last_upq);
			device->SendPfc(last_upq, 1);
			m_mmu->SetResume(inDev, qIndex);
		}	
	}
}

//shishi codes
void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	if(m_ccMode == 4) {
		SwitchNotifyDequeue_BFC(ifIndex,qIndex,p);
		return;
	}
	if(m_ccMode == 2) {
		FlowIdTag t;
		p->PeekPacketTag(t);

		CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
		ch.getInt = 1; // parse INT header
		p->PeekHeader(ch);
		uint32_t p_size = p->GetSize()- (ch.udp.ih.maxHop-ch.udp.ih.nhop) * 8;
		if((ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)  && p_size < 60)
			p_size = 60;

		if (qIndex != 0){
			uint32_t inDev = t.GetFlowId();
			// m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
			// m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
			m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p_size);
			m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p_size);
			m_bytes[inDev][ifIndex][qIndex] -= p_size;
			if (qIndex == 4){
				// uint8_t* buf = p->GetBuffer();
				// if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ 
				// 	IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6];
				// 	ih->SetnHopZero();
				// }
				PppHeader ppp;
				Ipv4Header h;
				bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
				if (egressCongested){
					printf("%08x %08x Switch SetEcn \n",ch.sip,ch.dip);
					p->RemoveHeader(ppp);
					p->RemoveHeader(h);
					h.SetEcn((Ipv4Header::EcnType)0x03);
					p->AddHeader(h);
					p->AddHeader(ppp);
				}
			} 
			//CheckAndSendPfc(inDev, qIndex);
			CheckAndSendResume(inDev, qIndex);
		}
		if (qIndex == 3){
			uint8_t* buf = p->GetBuffer();
			if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
				IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
				Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
				// ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes1[ifIndex][qIndex], dev->GetQueue()->GetNBytes(qIndex), dev->GetDataRate().GetBitRate());//shishi
				p_size += 8;
				// printf("%lu,%08x,%08x,switchID=%u,ifIndex=%u,%lu,%u,%u,%.3lf\n",Simulator::Now().GetTimeStep(),ch.sip,ch.dip,m_ecmpSeed,ifIndex,m_txBytes[ifIndex],p_size,dev->GetQueue()->GetNBytesTotal(),dev->GetDataRate().GetBitRate() * 1e-9);
			}
			uint64_t edge = ((uint64_t)ch.sip << 32) | ch.dip;
			--m_flowTable[edge].first;
		}
		m_txBytes[ifIndex] += p_size;//p->getsize
		
		// if(cnt>100000) {
		// 	cnt = 0;
		// 	m_heap.clear();
		// }
	}
	else {
		FlowIdTag t;
		p->PeekPacketTag(t);
		if (qIndex != 0){
			uint32_t inDev = t.GetFlowId();
			m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
			m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
			m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
			if (m_ecnEnabled){
				bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
				if (egressCongested){
					PppHeader ppp;
					Ipv4Header h;
					p->RemoveHeader(ppp);
					p->RemoveHeader(h);
					uint32_t sip = h.GetSource().Get();
					uint32_t dip = h.GetDestination().Get();
					// printf("%08x %08x Switch SetEcn \n",sip,dip);
					h.SetEcn((Ipv4Header::EcnType)0x03);
					p->AddHeader(h);
					p->AddHeader(ppp);
				}
			}
			//CheckAndSendPfc(inDev, qIndex);
			CheckAndSendResume(inDev, qIndex);
		}
		if (1){
			uint8_t* buf = p->GetBuffer();
			if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
				IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
				Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
				if (m_ccMode == 3 ){ // HPCC
					ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
				}else if (m_ccMode == 10){ // HPCC-PINT
					uint64_t t = Simulator::Now().GetTimeStep();
					uint64_t dt = t - m_lastPktTs[ifIndex];
					if (dt > m_maxRtt)
						dt = m_maxRtt;
					uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
					uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
					double newU;

					/**************************
					 * approximate calc
					 *************************/
					int b = 20, m = 16, l = 20; // see log2apprx's paremeters
					int sft = logres_shift(b,l);
					double fct = 1<<sft; // (multiplication factor corresponding to sft)
					double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
					double log_B = log2(B)*fct; // log2(B)*fct
					double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
					double qterm = 0;
					double byteTerm = 0;
					double uTerm = 0;
					if ((qlen >> 8) > 0){
						int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
						int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
						qterm = pow(2, (
									log_dt + log_qlen + log_1e9 - log_B - 2*log_T
									)/fct
								) * 256;
						// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
					}
					if (m_lastPktSize[ifIndex] > 0){
						int byte = m_lastPktSize[ifIndex];
						int log_byte = log2apprx(byte, b, m, l);
						byteTerm = pow(2, (
									log_byte + log_1e9 - log_B - log_T
									)/fct
								);
						// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
					}
					if (m_maxRtt > dt && m_u[ifIndex] > 0){
						int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
						int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
						uTerm = pow(2, (
									log_T_dt + log_u - log_T
									)/fct
								) / 8192;
						// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
					}
					newU = qterm+byteTerm+uTerm;

					#if 0
					/**************************
					 * accurate calc
					 *************************/
					double weight_ewma = double(dt) / m_maxRtt;
					double u;
					if (m_lastPktSize[ifIndex] == 0)
						u = 0;
					else{
						double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
						u = (qlen / m_maxRtt + txRate) * 1e9 / B;
					}
					newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
					printf(" %lf\n", newU);
					#endif

					/************************
					 * update PINT header
					 ***********************/
					uint16_t power = Pint::encode_u(newU);
					if (power > ih->GetPower())
						ih->SetPower(power);

					m_u[ifIndex] = newU;
				}
			}
		}
		m_txBytes[ifIndex] += p->GetSize();
		m_lastPktSize[ifIndex] = p->GetSize();
		m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
	}
	// printf("%lu %lu\n",((Simulator::Now() - fresh).GetTimeStep() - 2000000000),m_heap.size());
	
}

// void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
// 	FlowIdTag t;
// 	p->PeekPacketTag(t);
// 	if (qIndex != 0){
// 		uint32_t inDev = t.GetFlowId();
// 		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
// 		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
// 		m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
// 		if (m_ecnEnabled){
// 			bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
// 			if (egressCongested){
// 				PppHeader ppp;
// 				Ipv4Header h;
// 				p->RemoveHeader(ppp);
// 				p->RemoveHeader(h);
// 				h.SetEcn((Ipv4Header::EcnType)0x03);
// 				p->AddHeader(h);
// 				p->AddHeader(ppp);
// 			}
// 		}
// 		//CheckAndSendPfc(inDev, qIndex);
// 		CheckAndSendResume(inDev, qIndex);
// 	}
// 	if (1){
// 		uint8_t* buf = p->GetBuffer();
// 		if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
// 			IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
// 			Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
// 			if (m_ccMode == 3){ // HPCC
// 				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
// 			}else if (m_ccMode == 10){ // HPCC-PINT
// 				uint64_t t = Simulator::Now().GetTimeStep();
// 				uint64_t dt = t - m_lastPktTs[ifIndex];
// 				if (dt > m_maxRtt)
// 					dt = m_maxRtt;
// 				uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
// 				uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
// 				double newU;

// 				/**************************
// 				 * approximate calc
// 				 *************************/
// 				int b = 20, m = 16, l = 20; // see log2apprx's paremeters
// 				int sft = logres_shift(b,l);
// 				double fct = 1<<sft; // (multiplication factor corresponding to sft)
// 				double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
// 				double log_B = log2(B)*fct; // log2(B)*fct
// 				double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
// 				double qterm = 0;
// 				double byteTerm = 0;
// 				double uTerm = 0;
// 				if ((qlen >> 8) > 0){
// 					int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
// 					int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
// 					qterm = pow(2, (
// 								log_dt + log_qlen + log_1e9 - log_B - 2*log_T
// 								)/fct
// 							) * 256;
// 					// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
// 				}
// 				if (m_lastPktSize[ifIndex] > 0){
// 					int byte = m_lastPktSize[ifIndex];
// 					int log_byte = log2apprx(byte, b, m, l);
// 					byteTerm = pow(2, (
// 								log_byte + log_1e9 - log_B - log_T
// 								)/fct
// 							);
// 					// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
// 				}
// 				if (m_maxRtt > dt && m_u[ifIndex] > 0){
// 					int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
// 					int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
// 					uTerm = pow(2, (
// 								log_T_dt + log_u - log_T
// 								)/fct
// 							) / 8192;
// 					// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
// 				}
// 				newU = qterm+byteTerm+uTerm;

// 				#if 0
// 				/**************************
// 				 * accurate calc
// 				 *************************/
// 				double weight_ewma = double(dt) / m_maxRtt;
// 				double u;
// 				if (m_lastPktSize[ifIndex] == 0)
// 					u = 0;
// 				else{
// 					double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
// 					u = (qlen / m_maxRtt + txRate) * 1e9 / B;
// 				}
// 				newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
// 				printf(" %lf\n", newU);
// 				#endif

// 				/************************
// 				 * update PINT header
// 				 ***********************/
// 				uint16_t power = Pint::encode_u(newU);
// 				if (power > ih->GetPower())
// 					ih->SetPower(power);

// 				m_u[ifIndex] = newU;
// 			}
// 		}
// 	}
// 	m_txBytes[ifIndex] += p->GetSize();
// 	m_lastPktSize[ifIndex] = p->GetSize();
// 	m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
// }

int SwitchNode::logres_shift(int b, int l){
	static int data[] = {0,0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5};
	return l - data[b];
}

int SwitchNode::log2apprx(int x, int b, int m, int l){
	int x0 = x;
	int msb = int(log2(x)) + 1;
	if (msb > m){
		x = (x >> (msb - m) << (msb - m));
		#if 0
		x += + (1 << (msb - m - 1));
		#else
		int mask = (1 << (msb-m)) - 1;
		if ((x0 & mask) > (rand() & mask))
			x += 1<<(msb-m);
		#endif
	}
	return int(log2(x) * (1<<logres_shift(b, l)));
}

} /* namespace ns3 */
