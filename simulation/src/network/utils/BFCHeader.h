#ifndef BFC_HEADER_H
#define BFC_HEADER_H

#include "ns3/buffer.h"

namespace ns3 {
/**
 * \ingroup ipv4
 *
 * \brief Custom packet header
 */
class BFCHeader {
public:
  /**
   * \brief Construct a null custom header
   */
  BFCHeader ();
  static uint32_t GetStaticSize();
  void Serialize (Buffer::Iterator start) const;
  uint32_t Deserialize (Buffer::Iterator start);

  uint32_t upstreamQueue;
  uint32_t counterIncr;
  
};

} // namespace ns3

#endif /* CUSTOM_HEADER_H */