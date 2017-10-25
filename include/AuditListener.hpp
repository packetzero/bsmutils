#ifndef _AUDIT_LISTENER_H_
#define _AUDIT_LISTENER_H_

#include <stdint.h>
#include <bsm/libbsm.h>
#include <vector>

namespace bsmutils
{
  class AuditListener
  {
  public:
    /*
     * Return false to skip record (based on header event_type).
     * This is more performant,
     * Based on the event_type in a record's header
     */
    virtual bool isWantedRecord(uint16_t hdr_event_type) = 0;
 
    /*
     * Called for every record where isWantedRecord() returns true.
     * Listener must make a copy of tokens if it wants to keep reference to the
     * data.
     */
    virtual void onRecord(uint16_t hdr_event_type, std::vector<tokenstr_t> &tokens)=0;
  };
}

#endif // _AUDIT_LISTENER_H_

