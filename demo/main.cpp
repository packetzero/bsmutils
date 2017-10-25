#include <stdio.h>
#include <string.h> // strstr
#include "../include/bsmutils.hpp"
using namespace bsmutils;

void print_usage()
{
  printf("usage: bsmdemo [-f] [filename]\n");
  printf("where:\n");
  printf("  -f       Performs a 'tail -f' on /dev/auditpipe\n");
  printf("  filename File to process and exit.\n");
}


int main(int argc, char *argv[])
{
  if (argc <= 1) {
    print_usage();
    return (0);
  }
  
  AuditListener* listener = NewAuditListenerLoginPrinter(true, false, stdout);
  

  if (strstr(argv[1], "-f") != 0L) {
    // do a tail -f /dev/auditpipe
  } else {
    // process file
    traverse_records(argv[1], listener);
  }

  return 0;
}
