#ifndef _BSMPP_HPP_
#define _BSMPP_HPP_

#include <stdio.h>
#include <stdint.h>
#include <bsm/libbsm.h>

#include <vector>
#include <string>

#include "AuditListener.hpp"

#define ERR_AUREAD_SHORT   -2
#define ERR_AUREAD_INVALID -3  // bad recsize or filenamelen
#define ERR_AUREAD_NOMEM   -4  // unable to allocate memory in dest
#define ERR_AUREAD_UNKNOWN -5  // value of type is not recognized

#define NO_SUCH_RETVAL 99999

namespace bsmutils
{
  /*
   * au_read_rec2()
   * Caller must ensure fp is not NULL.
   * Returns bytes read in dest.
   * @returns On success, length of record read into 'dest'.
   *     Otherwise error status: ERR_AUREAD_XX
   * NOTE: if ERR_AUREAD_SHORT is returned, file is rewound to position at start of record.
   */
  int au_read_rec2(FILE *fp, /* INOUT */ std::vector<unsigned char> &dest);

  /*
   * returns the event_type of token struct.
   */
  uint16_t get_event_type(tokenstr_t &tok);

  /*
   * returns return value in record.
   */
  uint32_t get_record_return_value(std::vector<tokenstr_t> &tokens, uint32_t defVal = NO_SUCH_RETVAL);

  /*
   * returns true if return value if value != 0, or no return token.
   */
  bool has_failure_return(std::vector<tokenstr_t> &tokens);

  /*
   * looks for str in 'text' tokens.
   */
  bool text_contains(std::vector<tokenstr_t> &tokens, std::string str);

  /*
   * returns value of last 'text' token found in tokens.
   */
  std::string get_text(std::vector<tokenstr_t> &tokens);

  /*
   * Returns pointer to token struct in tokens if found, otherwise 0L
   * usually the second record after the 'header'
   */
  tokenstr_t* find_subject_token(std::vector<tokenstr_t> &tokens);

  /*
   * Returns readable ip-address (IPV4 or IPV6) in subject token, or empty-string if not found.
   */
  std::string get_subject_ipaddr_str(tokenstr_t& tok);

  /*
   * Returns uid of subject token.
   */
  uint32_t get_subject_userid(tokenstr_t& tok);
  
  
  void traverse_records(const char *filename, AuditListener *listener);

};
extern bsmutils::AuditListener* NewAuditListenerLoginPrinter(bool printTokenIds, bool printWantedRecordDetails, FILE *outfp);


#endif // _BSMPP_HPP_
