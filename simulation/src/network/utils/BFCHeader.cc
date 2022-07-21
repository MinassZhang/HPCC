#include "BFCHeader.h"

namespace ns3 {
BFCHeader::BFCHeader() {
    upstreamQueue = 0;
    counterIncr = 0;
}   

uint32_t BFCHeader::GetStaticSize(){
	return sizeof(upstreamQueue) + sizeof(counterIncr);
}

void BFCHeader::Serialize (Buffer::Iterator start) const{
	Buffer::Iterator i = start;
    i.WriteU32(upstreamQueue);
    i.WriteU32(counterIncr);
}

uint32_t BFCHeader::Deserialize (Buffer::Iterator start){
	Buffer::Iterator i = start;
    upstreamQueue = i.ReadU32();
    counterIncr = i.ReadU32();
	return GetStaticSize();
}

}