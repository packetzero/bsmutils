#ifndef _BSMPP_HPP_
#define _BSMPP_HPP_

#include <stdio.h>
#include <vector>

#define ERR_AUREAD_SHORT   -2
#define ERR_AUREAD_INVALID -3  // bad recsize or filenamelen
#define ERR_AUREAD_NOMEM   -4  // unable to allocate memory in dest
#define ERR_AUREAD_UNKNOWN -5  // value of type is not recognized
/*
 * au_read_rec2()
 * Caller must ensure fp is not NULL.
 * Returns bytes read in dest.
 * @returns On success, length of record read into 'dest'.
 *     Otherwise error status: ERR_AUREAD_XX
 * NOTE: if ERR_AUREAD_SHORT is returned, file is rewound to position at start of record.
 */
int au_read_rec2(FILE *fp, /* INOUT */ std::vector<u_char> &dest);


#endif // _BSMPP_HPP_
