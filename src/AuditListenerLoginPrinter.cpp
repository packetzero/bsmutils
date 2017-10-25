
#include "../include/bsmutils.hpp"

#include <bsm/audit_uevents.h>
#include <bsm/audit_kevents.h>

using namespace bsmutils;
using namespace std;

class AuditListenerLoginPrinter : public AuditListener
{
public:
  AuditListenerLoginPrinter(bool printTokenIds, bool printWantedRecordDetails, FILE *outfp) :
    _printTokenIds(printTokenIds), _printWantedRecordDetails(printWantedRecordDetails), _outfp(outfp) {
    
  }

  /*
   * Return false to skip record (based on header event_type).
   * This is more performant,
   * Based on the event_type in a record's header
   */
  virtual bool isWantedRecord(uint16_t hdr_event_type)
  {
    
    if (_shouldSkipEvent(hdr_event_type)) return false;
    
    if (_printTokenIds) fprintf(_outfp, "  event_type=0x%x(%d)\n", hdr_event_type, hdr_event_type);

    return _wantEvent(hdr_event_type);
  }
  
  /*
   * Called for every record where isWantedRecord() returns true.
   * Listener must make a copy of tokens if it wants to keep reference to the
   * data.
   */
  virtual void onRecord(uint16_t hdr_event_type, std::vector<tokenstr_t> &tokens)
  {
    if (_printWantedRecordDetails && hdr_event_type > 45000) _printRecordDetails(tokens);

    switch(hdr_event_type)
    {
      case AUE_openssh:
      {
        string ipAddrStr;
        tokenstr_t* tokSubj = find_subject_token(tokens);
        if (0L != tokSubj)
          ipAddrStr = get_subject_ipaddr_str(*tokSubj);
        bool isFailure = has_failure_return(tokens);
        //&& text_contains(tokens, "invalid")) {
        // TODO: forward ssh login error
        fprintf(_outfp, "SSH status:%c addr:%s text:'%s'\n", (isFailure?'F':'S'), ipAddrStr.c_str() , get_text(tokens).c_str());
        
        break;
      }
      case AUE_ssauthint:
      {
        string username = get_text(tokens);
        fprintf(_outfp, "Login status:%c username:%s\n", (has_failure_return(tokens) ? 'F' : 'S'), username.c_str());
        break;
      }
      case AUE_auth_user:
      {
        uint32_t retval = get_record_return_value(tokens);
        if (retval == 5000) {
          // unknown error, usually from auto-login test: SKIP
          
          break;
        }
        uint32_t uid = 99999;
        tokenstr_t* tokSubj = find_subject_token(tokens);
        if (0L != tokSubj)
          uid = get_subject_userid(*tokSubj);
        
        // TODO: filter out success for : Verify password .. _mbsetupuser  ?
        
        fprintf(_outfp, "Auth status:%c (%d) uid:%d text:%s\n", (retval == 0 ? 'S' :'F'), retval, uid, get_text(tokens).c_str());
        break;
      }
      default:
        break;
    }
  }

private:
  bool  _printTokenIds;
  bool  _printWantedRecordDetails;
  FILE* _outfp;
  
  bool _shouldSkipEvent(uint16_t event_type)
  {
    switch (event_type) {
      case AUE_SETSOCKOPT:
      case AUE_TASKNAMEFORPID:
      case AUE_RECVFROM:
      case AUE_RECVMSG:
      case AUE_SENDTO:
      case AUE_SENDMSG:
      case AUE_SETGID:
      case AUE_SETGROUPS:
      case AUE_SETPGRP:
      case AUE_SETPRIORITY:
      case AUE_PTHREADSIGMASK:
        return true;
      default:
        break;
    }
    return false;
  }

  bool _wantEvent(uint16_t event_type)
  {
    switch (event_type) {
      //case AUE_SETLOGIN: // of process? runas()?
      case AUE_openssh:   // lo
      case AUE_ssauthint: // aa
      case AUE_auth_user: // aa (screensaver login)
        return true;
      default:
        break;
    }
    return false;
  }

  void _printRecordDetails(std::vector<tokenstr_t> &tokens)
  {
    for (int i=0;i<tokens.size(); i++)
    {
      fprintf(_outfp, "   ");
      au_print_flags_tok(_outfp, &tokens[i], ",", AU_OFLAG_NONE);
      fprintf(_outfp, "\n");
    }
    fflush(stdout);
  }
};

AuditListener* NewAuditListenerLoginPrinter(bool printTokenIds, bool printWantedRecordDetails, FILE *outfp)
{
  return new AuditListenerLoginPrinter(printTokenIds, printWantedRecordDetails, outfp);
}

