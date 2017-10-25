#include "../openbsm/sys/bsm/audit.h"
#include "../openbsm/bsm/libbsm.h"

#include "../openbsm/compat/endian.h"

#include "../include/AuditListener.hpp"
#include "../include/bsmutils.hpp"

using namespace std;

#define FILENAMELEN_OFFSET (1 + 4 + 4)  // rectype_8 , seconds_32, millis_32
#define ABSURDLY_LONG_FILENAME_LENGTH 8192

namespace bsmutils
{
  
static inline bool au_is_valid_record_header(u_int8_t rectype)
{
  switch (rectype)
  {
    case AUT_HEADER32:
    case AUT_HEADER32_EX:
    case AUT_HEADER64:
    case AUT_HEADER64_EX:
    case AUT_OTHER_FILE32:
      return true;
    default:
      break;
  }

  return false;
}

/*
 * Read a record from the file pointer, store data in buf memory for buf is
 * also allocated in this function and has to be free'd outside this call.
 *
 * au_read_rec2() handles two possibilities: a stand-alone file token, or a
 * complete audit record.
 *
 * XXXRW: Note that if we hit an error, we leave the stream in an unusable
 * state, because it will be partly offset into a record.  We should rewind
 * or do something more intelligent.  Particularly interesting is the case
 * where we perform a partial read of a record from a non-blockable file
 * descriptor.  We should return the partial read and continue...?
 */
int
au_read_rec2(FILE *fp, std::vector<u_char> &dest)
{
	u_char *bptr;
	u_int32_t recsize;
	u_int32_t bytestoread;
	u_char rectype;
	u_int16_t filenamelen;

  // read at least the size of au_header32_t bytes,
  // the min size of all headers

  int peeksize = 17; // packed sizeof(au_header32_t)... compiler reorders size to 20
  dest.resize(peeksize);
  bptr = dest.data();
  size_t readlen = fread(bptr, 1, peeksize, fp);
  if (readlen < peeksize) {

    // if we at least have the rectype.  Valiate it

    if (readlen >= 1 && false == au_is_valid_record_header(*bptr))
      return ERR_AUREAD_UNKNOWN;

    // rewind back to beginning of record

    if (readlen > 0) fseek(fp, 0-readlen, SEEK_CUR);

    return ERR_AUREAD_SHORT;
  }

  // rectype is first byte

  rectype = bptr[0];

	switch (rectype) {
	case AUT_HEADER32:           // This is the only value I've observed, even with audit_control flags=all
	case AUT_HEADER32_EX:
	case AUT_HEADER64:
	case AUT_HEADER64_EX:
    // record size follows the rectype byte
    recsize = be32toh(*((u_int32_t*)(bptr + 1)));

		/* Check for recsize sanity */
		if (recsize < peeksize) {
			return ERR_AUREAD_INVALID;
		}

    // resize to include entire record
    try {
      dest.resize(recsize);
      bptr = dest.data();  // resize may reallocate, reacquire ptr
    } catch (std::exception &ex) {
      return ERR_AUREAD_NOMEM;
    }

		/* now read remaining record bytes */
		bytestoread = recsize - peeksize;
    if (bytestoread > 0) {

      readlen = fread(bptr + peeksize, 1, bytestoread, fp);

      if (readlen < bytestoread) {
        // if (readlen < 0) readlen = 0;  // size_t is unsigned, so always >= 0
        // rewind to beginning of record
        fseek(fp, 0 - peeksize-readlen, SEEK_CUR);

        return ERR_AUREAD_SHORT;
      }
    }

		break;

	case AUT_OTHER_FILE32:
		/*
		 * The file token (au_file_t) is variable-length, as it includes a
		 * pathname.  As a result, we have to read incrementally
		 * until we know the total length, then allocate space and
		 * read the rest.

     typedef struct {
       u_int32_t	 s;
       u_int32_t	 ms;
       u_int16_t	 len;
     	 char		*name;
     } au_file_t;

		 */
    filenamelen = ntohs(*(u_int16_t*)(bptr + FILENAMELEN_OFFSET));
    if (filenamelen <= 0 || filenamelen > ABSURDLY_LONG_FILENAME_LENGTH) {
      return ERR_AUREAD_INVALID;
    }
		recsize = FILENAMELEN_OFFSET + sizeof(filenamelen) + filenamelen;
    dest.resize(recsize);

    /* now read remaining record bytes */
		bytestoread = recsize - peeksize;
    if (bytestoread > 0) {

      readlen = fread(bptr + peeksize, 1, bytestoread, fp);

      if (readlen < bytestoread) {
        //if (readlen < 0) readlen = 0; // size_t is unsigned, so always >= 0
        // rewind to beginning of record
        fseek(fp, 0 - peeksize-readlen, SEEK_CUR);

        return ERR_AUREAD_SHORT;
      }
    }

		break;

	default:
		return ERR_AUREAD_UNKNOWN;
	}

	return (recsize);
}



void traverse_records(FILE *fp, AuditListener *listener)
{
  vector<uint8_t> vec;
  vector<tokenstr_t> tokens;
  
  bool verbose = true;
  u_char *buf;
  //  tokenstr_t tok;
  int reclen;
  int bytesread;
  
  while ((reclen = au_read_rec2(fp, vec)) > 0) {
    int numTokens = 0;
    uint16_t hdr_event_type = 0;
    buf = vec.data();
    tokens.clear();
    bytesread = 0;
    
    while (bytesread < reclen)
    {
      tokens.resize(numTokens + 1);
      tokenstr_t &tok = tokens[numTokens++];
      
      // read token
      if (-1 == au_fetch_tok(&tok, buf + bytesread, reclen - bytesread)) {
        break; // incomplete record
      }
      
      if (bytesread == 0)
      {
        hdr_event_type = get_event_type(tok);
        if (!listener->isWantedRecord(hdr_event_type)) break;
      }
      
      bytesread += tok.len;
    }
    
    if (tokens.size() > 1) {
      listener->onRecord(hdr_event_type, tokens);
    }
  }
}

void traverse_records(const char *filename, AuditListener *listener)
{
  FILE *fp = fopen(filename, "r");
  if (0L == fp) {
    printf("ERROR: unable to open file for reading '%s'\n", filename);
    return;
  }
  
  printf("Processing Audit file:%s\n", filename);
  
  traverse_records(fp, listener);
  
  fclose(fp);
}
  
} // namespace bsmutils
