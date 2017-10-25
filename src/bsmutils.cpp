#include "../include/bsmutils.hpp"
#include <arpa/inet.h> // inet_ntop
using namespace std;

namespace bsmutils
{
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


uint32_t get_record_return_value(vector<tokenstr_t> &tokens, uint32_t defVal)
{
    for (int i=tokens.size() - 1; i > 0; i--) {
        tokenstr_t &tok = tokens[i];
        if (tok.id == AUT_RETURN32) {
            return tok.tt.ret32.ret;
        } else if (tok.id == AUT_RETURN64) {
            return tok.tt.ret64.err;
        }
    }
    return defVal;
}

bool has_failure_return(vector<tokenstr_t> &tokens)
{
    uint32_t val = get_record_return_value(tokens);
    //if (val == NO_SUCH_RETVAL) return true;
    return val != 0;
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
    char tmpbuf[72];
    string val;
    switch (tok.id) {
        case AUT_SUBJECT32_EX:
        {
            uint32_t fam = (tok.tt.subj32_ex.tid.type == AU_IPv6 ? AF_INET6 : AF_INET);
            if (0L != inet_ntop(fam, &tok.tt.subj32_ex.tid.addr[0], tmpbuf, sizeof(tmpbuf))) {
                val = string(tmpbuf);
            }
            break;
        }
        case AUT_SUBJECT32:
        {
            if (0L != inet_ntop(AF_INET, &tok.tt.subj32.tid.addr, tmpbuf, sizeof(tmpbuf))) {
                val = string(tmpbuf);
            }
            break;
        }
    }
    return val;
}

uint32_t get_subject_userid(tokenstr_t& tok)
{
    switch (tok.id) {
        case AUT_SUBJECT32_EX:
            return tok.tt.subj32_ex.euid;
        case AUT_SUBJECT32:
            return tok.tt.subj32.euid;
        default: break;
    }
    return (uint32_t)-1;
}

} // namespace bsmutils
