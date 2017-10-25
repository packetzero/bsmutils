#include <gtest/gtest.h>

#include "../include/bsmutils.hpp"
using namespace std;
#include "../openbsm/sys/bsm/audit.h"
#include "../openbsm/sys/bsm/audit_kevents.h"
#include "../openbsm/bsm/libbsm.h"
#include <stdio.h>

using namespace bsmutils;

class ReadTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  // virtual void TearDown() {}
};



// tests start here

TEST_F(ReadTest, standard)
{
  FILE *fp = fopen("./testdata/au_file1", "r");
  ASSERT_TRUE(fp != 0L);

  vector<uint8_t> vec;
  int recsize = au_read_rec2(fp, vec);
  ASSERT_TRUE(recsize > 0);
  ASSERT_EQ(144, recsize);

  uint8_t* bptr = vec.data();

  ASSERT_EQ(AUT_HEADER32, *bptr);

  // cmopare bytes from hexdump

  ASSERT_EQ(0x01, bptr[0x10]);
  ASSERT_EQ(0x00, bptr[0x20]);
  ASSERT_EQ(0x01, bptr[0x30]);
  ASSERT_EQ(0x20, bptr[0x40]);
  ASSERT_EQ(0x63, bptr[0x50]);
  ASSERT_EQ(0x27, bptr[0x60]);
  ASSERT_EQ(0x65, bptr[0x70]);
  ASSERT_EQ(0x74, bptr[0x80]);
  ASSERT_EQ(0x90, bptr[0x8f]);

  fclose(fp);
}


TEST_F(ReadTest, short_unknown)
{
  FILE *fp = fopen("./testdata/au_short_invalid", "r");
  ASSERT_TRUE(fp != 0L);

  vector<uint8_t> vec;
  int recsize = au_read_rec2(fp, vec);
  ASSERT_EQ(ERR_AUREAD_UNKNOWN, recsize);

  fclose(fp);
}

TEST_F(ReadTest, short)
{
  FILE *fp = fopen("./testdata/au_short", "r");
  ASSERT_TRUE(fp != 0L);

  vector<uint8_t> vec;
  int recsize = au_read_rec2(fp, vec);
  ASSERT_EQ(ERR_AUREAD_SHORT, recsize);

  // make sure rewind
  ASSERT_EQ(0L, ftell(fp));

  fclose(fp);
}

TEST_F(ReadTest, empty)
{
  FILE *fp = fopen("./testdata/au_empty", "r");
  ASSERT_TRUE(fp != 0L);

  vector<uint8_t> vec;
  int recsize = au_read_rec2(fp, vec);
  ASSERT_EQ(ERR_AUREAD_SHORT, recsize);

  fclose(fp);
}

// Based on the internals of au_read_rec2(), which does two fread() calls.
// One that is 17 bytes, then the rest of the record.  So this tests
// When that second read is zero.
TEST_F(ReadTest, short17)
{
  FILE *fp = fopen("./testdata/au_short_17", "r");
  ASSERT_TRUE(fp != 0L);

  vector<uint8_t> vec;
  int recsize = au_read_rec2(fp, vec);
  ASSERT_EQ(ERR_AUREAD_SHORT, recsize);

  // make sure rewind
  ASSERT_EQ(0L, ftell(fp));

  fclose(fp);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status= RUN_ALL_TESTS();
  return status;
}
