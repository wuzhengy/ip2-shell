/*

Copyright (c) 2012, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "handler/tau_handler.hpp"

#include "util/base64.hpp"
#include "util/escape_json.hpp" // for escape_json
#include "util/hex_util.hpp"
#include "util/json_util.hpp"
#include "util/response_buffer.hpp" // for appendf
#include "util/tau_constants.hpp"

#include <stdlib.h>
#include <stdio.h>
//#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include <math.h>

#include <string.h> // for strcmp()
#include <stdio.h>
#include <vector>
#include <map>
#include <cstdint>

extern "C" {
#include "rpc/local_mongoose.h"
#include "util/jsmn.h"
}

#include "ip2/session.hpp"
#include "ip2/session_status.hpp"
#include "ip2/hex.hpp"
#include "ip2/performance_counters.hpp"
#include "ip2/aux_/common_data.h"
#include "ip2/blockchain/block.hpp"
#include "ip2/blockchain/transaction.hpp"
#include "ip2/communication/message.hpp"
/* *.pcap file format  =  file header(24B) + pkt header(16B) + Frame 
 * Frame  =  Ethernet header(14B) + IP header(20B) + UDP header(8B) + appdata */


//enhernet header (14B)
typedef struct _eth_hdr  
{  
    unsigned char dstmac[6]; //目标mac地址   
    unsigned char srcmac[6]; //源mac地址   
     unsigned short eth_type; //以太网类型   
}eth_hdr; 


//IP header 20B
typedef struct _ip_hdr  
{  
    unsigned char ver_hlen; //版本    
    unsigned char tos;       //服务类型   
    unsigned short tot_len;  //总长度   
    unsigned short id;       //标志   
    unsigned short frag_off; //分片偏移   
    unsigned char ttl;       //生存时间   
    unsigned char protocol;  //协议   
    unsigned short chk_sum;  //检验和   
    struct in_addr srcaddr;  //源IP地址   
    struct in_addr dstaddr;  //目的IP地址   
}ip_hdr;
  

//udp header  8B
typedef struct _udp_hdr  
{  
    unsigned short src_port; //远端口号   
    unsigned short dst_port; //目的端口号   
    unsigned short uhl;      //udp头部长度   
    unsigned short chk_sum;  //16位udp检验和   
}udp_hdr;

#define FILE_HEADER          24
#define FRAME_HEADER_LEN     (sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(udp_hdr))
#define NEED_HEADER_INFO     1 

using namespace ip2;

namespace ip2
{

void return_error(mg_connection* conn, char const* msg)
{
    mg_printf(conn, "HTTP/1.1 401 Invalid Request\r\n"
        "Content-Type: text/json\r\n"
        "Content-Length: %d\r\n\r\n"
        "{ \"result\": \"%s\" }", int(16 + strlen(msg)), msg);
}

void return_failure(std::vector<char>& buf, char const* msg, std::int64_t tag)
{
    buf.clear();
    appendf(buf, "{ \"result\": \"%s\", \"tag\": %" "I64d" "}", msg, tag);
}

struct method_handler
{
    char const* method_name;
    void (tau_handler::*fun)(std::vector<char>&, jsmntok_t* args, std::int64_t tag
        , char* buffer);
};

static method_handler handlers[] =
{
    {"session-stats", &tau_handler::session_stats},
    {"stop-io-service", &tau_handler::stop_io_service},
    {"restart-io-service", &tau_handler::restart_io_service},
    {"put-data-into-swarm", &tau_handler::put_data_into_swarm},
    {"relay-data-uri", &tau_handler::relay_data_uri},
    {"get-data-from-swarm", &tau_handler::get_data_from_swarm},
    {"relay-message", &tau_handler::relay_message},
};

void tau_handler::handle_json_rpc(std::vector<char>& buf, jsmntok_t* tokens , char* buffer)
{
    // we expect a "method" in the top level
    jsmntok_t* method = find_key(tokens, buffer, "method", JSMN_STRING);
    if (method == NULL)
    {
        std::cout << "missing method in request" << std::endl;
        return_failure(buf, "missing method in request", -1);
        return;
    }

    bool handled = false;
    buffer[method->end] = 0;
    char const* m = &buffer[method->start];
    jsmntok_t* args = NULL;
    for (int i = 0; i < sizeof(handlers)/sizeof(handlers[0]); ++i)
    {
        std::cout << "==================================" << std::endl;
        std::cout << "Method Name: " <<  handlers[i].method_name << std::endl;
        std::cout << "==================================" << std::endl;
        if (strcmp(m, handlers[i].method_name)) continue;

        args = find_key(tokens, buffer, "arguments", JSMN_OBJECT);
        std::int64_t tag = find_int(tokens, buffer, "tag");
        handled = true;

        if (args) {
			buffer[args->end] = 0;
        	printf("%s: %d, %s\n", m, args->type, args ? buffer + args->start : "{}");
		}

        (this->*handlers[i].fun)(buf, args, tag, buffer);
        std::cout << "Method Over" << std::endl;
        break;
    }

    if (!handled)
        printf("Unhandled: %s: %s\n", m, args ? buffer + args->start : "{}");

}

void tau_handler::session_stats(std::vector<char>& buf, jsmntok_t* args, std::int64_t tag, char* buffer)
{
    // TODO: post session stats instead, and capture the performance counters
    m_ses.post_session_stats();
    appendf(buf, "{ \"result\": \"post session status success\"}\n");
}

void tau_handler::stop_io_service(std::vector<char>& buf, jsmntok_t* args, std::int64_t tag, char* buffer)
{
    // TODO: post session stats instead, and capture the performance counters
    m_ses.stop_service();
    appendf(buf, "{ \"result\": \"stop io service success\"}\n");
}

void tau_handler::restart_io_service(std::vector<char>& buf, jsmntok_t* args, std::int64_t tag, char* buffer)
{
    // TODO: post session stats instead, and capture the performance counters
    m_ses.restart_service();
    appendf(buf, "{ \"result\": \"restart io service success\"}\n");
}

void tau_handler::put_data_into_swarm(std::vector<char>& buf, jsmntok_t* args, std::int64_t tag, char* buffer)
{
    jsmntok_t* b = find_key(args, buffer, "blob", JSMN_STRING);
    jsmntok_t* u = find_key(args, buffer, "uri", JSMN_STRING);

    //blob
    int size = b->end - b->start;
    buffer[b->end] = 0;
    char const* blob = &buffer[b->start];
    std::vector<char> blob_v;
	blob_v.insert(blob_v.end(), blob, blob+size);

    //uri
	const int len20 = 20;
    char const* uri = &buffer[u->start];
	std::array<char, len20> ua;
	for(int i = 0; i < len20; i++)
		ua[i] = uri[i];


	ip2::api::error_code ec = m_ses.put_data_into_swarm(blob_v, ua);

	if(0 == ec)
		appendf(buf, "{\"result\": \"%s\", \"uri\": %s}", "success", ua.data());
	else 
		appendf(buf, "{\"result\": \"%s\", \"error\": %d}", "failed", ec);
}

void tau_handler::relay_data_uri(std::vector<char>& buf, jsmntok_t* args, std::int64_t tag, char* buffer)
{
    jsmntok_t* r = find_key(args, buffer, "receiver", JSMN_STRING);
    jsmntok_t* u = find_key(args, buffer, "uri", JSMN_STRING);
    jsmntok_t* t = find_key(args, buffer, "timestamp", JSMN_PRIMITIVE);

    //receiver
    char const* receiver_pubkey_hex = &buffer[r->start];
    char* receiver_pubkey_char = new char[KEY_LEN];
    hex_char_to_bytes_char(receiver_pubkey_hex, receiver_pubkey_char, KEY_HEX_LEN);
	std::array<char, KEY_LEN> ra;
	for(int i = 0; i < KEY_LEN; i++)
		ra[i] = receiver_pubkey_char[i];

    //uri
	const int len20 = 20;
    char const* uri = &buffer[u->start];
	std::array<char, len20> ua;
	for(int i = 0; i < len20; i++)
		ua[i] = uri[i];

    //timestamp
    int timestamp = atoi(buffer + t->start);

	ip2::api::error_code ec = m_ses.relay_data_uri(ra, ua, timestamp);

	if(0 == ec)
		appendf(buf, "{\"result\": \"%s\"}", "success");
	else 
		appendf(buf, "{\"result\": \"%s\", \"error\": %d}", "failed", ec);
}

void tau_handler::get_data_from_swarm(std::vector<char>& buf, jsmntok_t* args, std::int64_t tag, char* buffer)
{
    jsmntok_t* s = find_key(args, buffer, "sender", JSMN_STRING);
    jsmntok_t* u = find_key(args, buffer, "uri", JSMN_STRING);
    jsmntok_t* t = find_key(args, buffer, "timestamp", JSMN_PRIMITIVE);

    //sender
    char const* sender_pubkey_hex = &buffer[s->start];
    char* sender_pubkey_char = new char[KEY_LEN];
    hex_char_to_bytes_char(sender_pubkey_hex, sender_pubkey_char, KEY_HEX_LEN);
	std::array<char, KEY_LEN> sa;
	for(int i = 0; i < KEY_LEN; i++)
		sa[i] = sender_pubkey_char[i];

    //uri
	const int len20 = 20;
    char const* uri = &buffer[u->start];
	std::array<char, len20> ua;
	for(int i = 0; i < len20; i++)
		ua[i] = uri[i];

    //timestamp
    int timestamp = atoi(buffer + t->start);

	ip2::api::error_code ec = m_ses.get_data_from_swarm(sa, ua, timestamp);

	if(0 == ec)
		appendf(buf, "{\"result\": \"%s\"}", "success");
	else 
		appendf(buf, "{\"result\": \"%s\", \"error\": %d}", "failed", ec);
}

void tau_handler::relay_message(std::vector<char>& buf, jsmntok_t* args, std::int64_t tag, char* buffer)
{
    jsmntok_t* r = find_key(args, buffer, "receiver", JSMN_STRING);
    jsmntok_t* m = find_key(args, buffer, "message", JSMN_STRING);

    //receiver
    char const* receiver_pubkey_hex = &buffer[r->start];
    char* receiver_pubkey_char = new char[KEY_LEN];
    hex_char_to_bytes_char(receiver_pubkey_hex, receiver_pubkey_char, KEY_HEX_LEN);
	std::array<char, KEY_LEN> ra;
	for(int i = 0; i < KEY_LEN; i++)
		ra[i] = receiver_pubkey_char[i];

    //message
    int size = m->end - m->start;
    buffer[m->end] = 0;
    char const* msg = &buffer[m->start];
    std::vector<char> msg_v;
	msg_v.insert(msg_v.end(), msg, msg + size);

	ip2::api::error_code ec = m_ses.relay_message(ra, msg_v);

	if(0 == ec)
		appendf(buf, "{\"result\": \"%s\"}", "success");
	else 
		appendf(buf, "{\"result\": \"%s\", \"error\": %d}", "failed", ec);
}

tau_handler::tau_handler(session& s, tau_shell_sql* sqldb, auth_interface const* auth, dht::public_key& pubkey, dht::secret_key& seckey)
    : m_ses(s)
    , m_db(sqldb)
    , m_auth(auth)
	, m_pubkey(pubkey)
	, m_seckey(seckey)
{

}

tau_handler::~tau_handler() {}

bool tau_handler::handle_http(mg_connection* conn, mg_request_info const* request_info)
{
    std::cout << "==============Incoming HTTP ==============" << std::endl;
    // we only provide access to paths under /web and /upload
    if (strcmp(request_info->uri, "/rpc"))
        return false;

    permissions_interface const* perms = parse_http_auth(conn, m_auth);
    if (perms == NULL)
    {    
        mg_printf(conn, "HTTP/1.1 401 Unauthorized\r\n"
            "WWW-Authenticate: Basic realm=\"BitTorrent\"\r\n"
            "Content-Length: 0\r\n\r\n");
        return true;
    } 

    char const* cl = mg_get_header(conn, "content-length");
    std::vector<char> post_body;
    if (cl != NULL)
    {
        int content_length = atoi(cl);
        if (content_length > 0 && content_length < 10 * 1024 * 1024)
        {
            post_body.resize(content_length + 1);
            mg_read(conn, &post_body[0], post_body.size());
            // null terminate
            post_body[content_length] = 0;
        }
    }

    printf("REQUEST: %s%s%s\n", request_info->uri
        , request_info->query_string ? "?" : ""
        , request_info->query_string ? request_info->query_string : "");

    std::vector<char> response;
    if (post_body.empty())
    {
        return_error(conn, "request with no POST body");
        return true;
    }
    jsmntok_t tokens[256];
    jsmn_parser p;
    jsmn_init(&p);

    int r = jsmn_parse(&p, &post_body[0], tokens, sizeof(tokens)/sizeof(tokens[0]));
    if (r == JSMN_ERROR_INVAL)
    {
        return_error(conn, "request not JSON");
        return true;
    }
    else if (r == JSMN_ERROR_NOMEM)
    {
        return_error(conn, "request too big");
        return true;
    }
    else if (r == JSMN_ERROR_PART)
    {
        return_error(conn, "request truncated");
        return true;
    }
    else if (r != JSMN_SUCCESS)
    {
        return_error(conn, "invalid request");
        return true;
    }

    handle_json_rpc(response, tokens, &post_body[0]);

    // we need a null terminator
    response.push_back('\0');
    // subtract one from content-length
    // to not count null terminator
    mg_printf(conn, "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/json\r\n"
        "Content-Length: %d\r\n\r\n", int(response.size()) - 1);
    mg_write(conn, &response[0], response.size());
    printf("%s\n", &response[0]);
    return true;
}

}
