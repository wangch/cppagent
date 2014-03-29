// 
// goagent.cpp : Defines the entry point for the console application.
//

#include <sdkddkver.h>
#include "common.h"
#include "gae_proxy.h"
#include "http/http_util.h"
#include "http/conn.h"
#include "http/server.h"

#define GLOG_NO_ABBREVIATED_SEVERITIES
#include <glog/logging.h>
#include <boost/filesystem.hpp>
#include <iostream>

namespace fs = boost::filesystem;


class ProxyHandler : public http::RequestHandler {
	http::HttpUtil& http_;
public:
	ProxyHandler(http::HttpUtil& http) : http_(http) {}
	virtual ~ProxyHandler() {}
	virtual int Handle(http::BaseConnPtr conn, const http::Request& req) {
		GAEProxyHandler gph(this->http_, const_cast<http::Request&>(req));
		return gph.Handle(conn);
	}
};


int main(int argc, char* argv[]) {
	// 初始化logging
	google::InitGoogleLogging(argv[0]);

	// 改变当前路径
	fs::current_path(fs::complete(argv[0]).branch_path());

	// 解析配置ini文件
	auto common = Common::Get();
	// 打印配置信息
	std::cout << common->Info();

	// 启动代理服务器
	http::server s(common->LISTEN_IP, common->LISTEN_PORT, 4);
	http::HttpUtil http(s.io_service());
	http::HandlerPtr handler(new ProxyHandler(http));
	s.run(handler);

	return 0;
}

