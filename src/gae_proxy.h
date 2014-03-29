//
// gae_proxy.h
//

#ifndef _GOAGENT_GAEPROXY_H_
#define _GOAGENT_GAEPROXY_H_

#include "http/request.h"
#include "http/conn.h"
#include "http/http_util.h"

class GAEProxyHandler : public http::RequestHandler {
	http::HttpUtil& http_;
	http::Request& req_;
	http::BaseConnPtr conn_;
	bool range_in_query_;
	bool special_range_;
	bool crlf_;
public:
	GAEProxyHandler(http::HttpUtil& http, http::Request& req);
	~GAEProxyHandler();
	virtual int Handle(http::BaseConnPtr conn, const http::Request& req);
	int Handle(http::BaseConnPtr conn);

private:
	int do_method();
	int do_fwd_method();
	int do_gae_method();
	int do_connect();
	int fwd();
	int gae_fwd();
	int read_payload_and_compress();
	void do_range(http::Request& req);
};

#endif // _GOAGENT_GAEPROXY_H_