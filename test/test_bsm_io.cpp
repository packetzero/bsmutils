#include <gtest/gtest.h>

#include "../include/bsmpp.hpp"
using namespace std;
#include "../openbsm/sys/bsm/audit.h"
#include "../openbsm/sys/bsm/audit_kevents.h"
#include "../openbsm/bsm/libbsm.h"
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop

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

uint16_t get_event_type(tokenstr_t &tok)
{
  uint16_t event_id=0;
  
  switch (tok.id) {
    case AUT_HEADER32:
      event_id = tok.tt.hdr32_ex.e_type;
      break;
    case AUT_HEADER32_EX:
      event_id = tok.tt.hdr32_ex.e_type;
      break;
    case AUT_HEADER64:
      event_id = tok.tt.hdr64.e_type;
      break;
    case AUT_HEADER64_EX:
      event_id = tok.tt.hdr64_ex.e_type;
      break;
  }
  return event_id;
}

bool should_skip_event(uint16_t event_type)
{
  switch (event_type) {
    case AUE_SETSOCKOPT:
    case AUE_TASKNAMEFORPID:
    case AUE_RECVFROM:
    case AUE_RECVMSG:
    case AUE_SENDTO:
    case AUE_SENDMSG:
    case AUE_SETGID:
    case AUE_SETGROUPS:     // could be useful
    case AUE_SETPGRP:
    case AUE_SETPRIORITY:
    case AUE_PTHREADSIGMASK:
      return true;
    default:
      break;
  }
  return false;
}
/*
32800:AUE_openssh:OpenSSH login:lo
 
45000:AUE_audit_startup:audit startup:ad
45001:AUE_audit_shutdown:audit shutdown:ad
45014:AUE_modify_password:modify password:ad
45015:AUE_create_group:create group:ad
45016:AUE_delete_group:delete group:ad
45017:AUE_modify_group:modify group:ad
45018:AUE_add_to_group:add to group:ad
45019:AUE_remove_from_group:remove from group:ad
45027:AUE_calife:Calife:ad
45029:AUE_audit_recovery:audit crash recovery:ad

45020:AUE_revoke_obj:revoke object priv:fm
 
45021:AUE_lw_login:loginwindow login:lo
45022:AUE_lw_logout:loginwindow logout:lo

45023:AUE_auth_user:user authentication:aa
45024:AUE_ssconn:SecSrvr connection setup:aa
45025:AUE_ssauthorize:SecSrvr AuthEngine:aa
45026:AUE_ssauthint:SecSrvr authinternal mech:aa
45028:AUE_sudo:sudo(1):aa
45030:AUE_ssauthmech:SecSrvr AuthMechanism:aa
45031:AUE_sec_assessment:Security Assessment:aa
*/

#define AUE_LO_LOGINWINDOW_LOGIN    45021
#define AUE_LO_LOGINWINDOW_LOGOUT   45022

#define AUE_AA_AUTH_USER            45023
#define AUE_AA_SECSRVR_CONSETUP     45024
#define AUE_AA_SECSRVR_AUTHENGINE   45025
#define AUE_AA_SECSRVR_AUTHINTERNAL 45026
#define AUE_AA_SUDO                 45028
#define AUE_AA_SECSRVR_AUTHMECH     45030


#define AUE_sudo 45028

#define AUE_LO_OPENSSH_LOGIN        32800

bool want_event(uint16_t event_type)
{
  switch (event_type) {
    case AUE_POSIX_SPAWN:
    case AUE_KILL:
    case AUE_SETLOGIN: // of process? runas()?
    case AUE_LO_OPENSSH_LOGIN:
    case AUE_AA_SECSRVR_AUTHINTERNAL:
      return true;
    default:
      break;
  }
  return false;
}

bool has_failure_return(vector<tokenstr_t> &tokens)
{
    for (int i=tokens.size() - 1; i > 0; i--) {
        tokenstr_t &tok = tokens[i];
        if (tok.id == AUT_RETURN32) {
            return (tok.tt.ret32.ret != 0);
        } else if (tok.id == AUT_RETURN64) {
            return (tok.tt.ret64.err != 0);
        }
    }
    return false;
}

bool text_contains(vector<tokenstr_t> &tokens, std::string str)
{
    for (int i=tokens.size() - 1; i > 0; i--) {
        tokenstr_t &tok = tokens[i];
        if (tok.id == AUT_TEXT) {
            return 0L != strstr(tok.tt.text.text, str.c_str());
        }
    }
    return false;
}

std::string get_text(vector<tokenstr_t> &tokens)
{
    string val;
    for (int i=tokens.size() - 1; i > 0; i--) {
        tokenstr_t &tok = tokens[i];
        if (tok.id == AUT_TEXT) {
            val = string(tok.tt.text.text);
            return val;
        }
    }
    return val;
}

// usually the second record after the 'header'
tokenstr_t* find_subject_token(vector<tokenstr_t> &tokens)
{
    for (int i=1; i < tokens.size()-1; i++) {
        switch (tokens[i].id) {
            case AUT_SUBJECT32:
            case AUT_SUBJECT32_EX:
            case AUT_SUBJECT64:
            case AUT_SUBJECT64_EX:
                return &tokens[i];
            default:
                break;
        }
    }
    return 0L;
}
std::string get_subject_ipaddr_str(tokenstr_t& tok)
{
    string val;
    switch (tok.id) {
        case AUT_SUBJECT32_EX:
        {
            char tmpbuf[32];
            uint32_t remoteAddrV4 = tok.tt.subj32.tid.addr;
            if (0L != inet_ntop(AF_INET, &tok.tt.subj32.tid.addr, tmpbuf, sizeof(tmpbuf))) {
                val = string(tmpbuf);
            }
            break;
        }
    }
    return val;
}

void process_record(uint16_t hdr_event_type, vector<tokenstr_t> &tokens)
{
    switch(hdr_event_type)
    {
        case AUE_LO_OPENSSH_LOGIN:
        {
            string ipAddrStr;
            tokenstr_t* tokSubj = find_subject_token(tokens);
            if (0L != tokSubj)
                ipAddrStr = get_subject_ipaddr_str(*tokSubj);
            bool isFailure = has_failure_return(tokens);
            //&& text_contains(tokens, "invalid")) {
                // TODO: forward ssh login error
            printf("SSH status:%c addr:%s text:'%s'\n", (isFailure?'F':'S'), ipAddrStr.c_str() , get_text(tokens).c_str());
            
            break;
        }
        case AUE_AA_SECSRVR_AUTHINTERNAL:
        {
            string username = get_text(tokens);
            printf("Login status:%c username:%s\n", (has_failure_return(tokens) ? 'F' : 'S'), username.c_str());
        }
        default:
            break;
    }
}

void traverse_records(FILE *fp)
{
    vector<uint8_t> vec;
    vector<tokenstr_t> tokens;
    
    bool verbose = false;
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
                
                if (should_skip_event(hdr_event_type)) break; // filter
                
                if (verbose) printf("tok.id=0x%x (%d)  event_type=0x%x(%d)\n", tok.id, tok.id, hdr_event_type, hdr_event_type);
                
                if (!want_event(hdr_event_type)) break;  // filter
            }
            
            if (verbose) {
                printf("   ");
                au_print_flags_tok(stdout, &tok, ",", AU_OFLAG_NONE);
                printf("\n");
                fflush(stdout);
            }
            
            bytesread += tok.len;
        }
        
        if (tokens.size() > 1) {
            process_record(hdr_event_type, tokens);
        }
    }
}

void traverse_records(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (0L == fp) {
        printf("ERROR: unable to open file for reading '%s'\n", filename);
        return;
    }
    
    printf("Processing Audit file:%s\n", filename);
    
    traverse_records(fp);
    
    fclose(fp);
}

TEST_F(ReadTest, filerec)
{
  traverse_records("./testdata/au_ssh");
}

TEST_F(ReadTest, file_logins2)
{
    traverse_records("./testdata/au_logins2");
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status= RUN_ALL_TESTS();
  return status;
}
