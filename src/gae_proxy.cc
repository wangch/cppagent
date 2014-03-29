 //
// gae_proxy.cc
//

#include "gae_proxy.h"
#include "common.h"
#include "base64.h"
#include "cert_util.h"
#include "http/respond.h"
#include "http/request.h"
#include "http/http_util.h"

#pragma warning(disable: 4251)
#define GLOG_NO_ABBREVIATED_SEVERITIES
#include <glog/logging.h>
#include <zlib/zlib.h>
#include <boost/algorithm/string.hpp>

#include <regex>
#include <thread>


GAEProxyHandler::GAEProxyHandler(http::HttpUtil& http, http::Request& req) 
	: http_(http), req_(req), crlf_(Common::Get()->GAE_CRLF == 1) {
}

GAEProxyHandler::~GAEProxyHandler() {

}

int GAEProxyHandler::do_method() {
	auto common = Common::Get();
	// 正则查找request host 是否匹配HOSTS_MATCH（是一个正则表达式）, 匹配则转发
	if (common->HOSTS_MATCH.size() > 0) {
		for (auto& x : common->HOSTS_MATCH) {
			std::regex re(x.first);
			if (std::regex_search(req_.host, re)) {
				return do_fwd_method();
			}
		}
	}

	for (auto& x : common->GOOGLE_SITES) {
		if (req_.host.find(x) != std::string::npos) {
			bool found = false;
			for (auto& s : common->GOOGLE_WITHGAE) {
				if (req_.host.find(s) != std::string::npos) {
					found = true;
					break;
				}
			}
			if (found) {
				break; // request host在GOOGLE_SITES中，不在GOOGLE_FORCEHTTPS中，跳出，使用gae
			}
			found = false;
			for (auto& s : common->GOOGLE_FORCEHTTPS) {
				if (req_.host.find(s) != std::string::npos) {
					found = true; 
					break;
				}
			}
			if (found) {  // request host在GOOGLE_FORCEHTTPS中
				std::string location = this->req_.url.rawurl;
				if (req_.url.scheme == "http") {
					location.replace(0, 4, "https");
				}
				http::Respond res = http::status_respond(http::status::moved_permanently);
				return this->conn_->Write(http::respond_msg(res));
			} else {
				return do_fwd_method();
			}
		}
	}

	return do_gae_method();
}

int GAEProxyHandler::do_fwd_method() {
	if (req_.url.scheme == "https") {
		return -1; // can't go here!!!
	}

	http::Respond res;
	int r = this->http_.DoRequest(this->req_, res, Common::Get()->GAE_CRLF == 1);
	if (r != 0) {
		return -1;
	}

	while (1) {
		boost::asio::streambuf data;
		r = res.body->Read(8192, data);
		if (r != 0) {
			return r;
		}
		r = this->conn_->Write(data);
		if (r != 0) {
			return r;
		}
	}
	return 0;
}

void GAEProxyHandler::do_range(http::Request& req) {
	auto common = Common::Get();
	bool range_in_query = req.uri.find("range=") != std::string::npos;
	bool special_range = false;
	for (auto& x : common->AUTORANGE_ENDSWITH) {
		if (boost::algorithm::ends_with(req.uri, x)) {
			special_range = true;
			break;
		}
	}
	if (special_range) {
		for (auto& x : common->AUTORANGE_NOENDSWITH) {
			if (boost::algorithm::ends_with(req.uri, x)) {
				special_range = false;
				break;
			}
		}
	}
	for (auto& x : common->AUTORANGE_HOSTS_MATCH) {
		std::regex re(x);
		if (std::regex_match(req.host, re)) {
			special_range = true;
			break;
		}
	}

	std::string range = req.header["Range"];
	if (range.size() > 0) {
		std::regex re("bytes=(\\d+)-");
		std::smatch m;
		int start = 0;
		if (std::regex_search(range, m, re)) {
			start = std::atoi(m[0].str().c_str());
		}
		req.header["Range"] = 
			std::to_string(start) + "-" + std::to_string(common->AUTORANGE_MAXSIZE-1);
	} else if (!range_in_query && special_range) {
		req.header["Range"] = "0"; 
		req.header["Range"] += "-" + std::to_string(common->AUTORANGE_MAXSIZE-1);
	}

	this->range_in_query_ = range_in_query;
	this->special_range_ = special_range;
}


int GAEProxyHandler::read_payload_and_compress() {
	http::Request& req = this->req_;
	auto local = this->conn_;
	// read payload
	if (req.header.find("Content-Length") != req.header.end()) {
		std::string cl(req.header["Content-Length"]);
		int len = std::atoi(cl.c_str());
		boost::asio::streambuf payload;
		int r = local->Read(len, payload);
		payload.commit(payload.size());

		if (r != 0) {
			return r;
		}

		const char* data = boost::asio::buffer_cast<const char*>(payload.data());
		req.body.reset(new std::vector<char>(data, data+len));
		req.body_len = len;

		if (len < 10 * 1024 * 1024 && req.header.find("Content-Encoding") != req.header.end()) {
			Bytef* out = new Bytef[len];
			unsigned long out_len = 0;
			r = compress(out, &out_len, (Bytef*)data, len);
			if (r != Z_OK) {
				delete [] out;
				return -1;
			}
			if (len <= (int)out_len) {
				delete [] out;
				return 0;
			}
			req.header["Content-Encoding"] = "deflate";
			out += 2;
			out_len -= 6;
			req.body.reset(new std::vector<char>(out, out + out_len));
			req.body_len = out_len;
			req.header["Content-Length"] = std::to_string(out_len);
		}
	} 
	return 0;
}

int packet_gae_request(const http::Request& req, http::Request& gae_req) {
	auto common = Common::Get();
	std::string metadata = "G-Method:" + req.method + "\nG-Url:" + req.url.rawurl;
	if (common->GAE_PASSWORD.size() > 0) {
		metadata += "\nG-password:" + common->GAE_PASSWORD;
	}
	if (common->GAE_VALIDATE != 0) {
		metadata += "\nG-password:";
		metadata += "1";
	}
	if (common->GAE_OBFUSCATE == 1 && 
		(req.header.find("X-Requested-With") == req.header.end())) {
		std::vector<std::string> g_abbv;
		for (auto it : req.header) {
			bool found = false;
			for (std::string s : http::skip_headers) {
				if (it.first == s) {
					found = true;
					break;
				}
			}
			if (!found) {
				for (auto item : http::abbv_headers) {
					if (item.first == it.first && item.second.second(it.second)) {
						g_abbv.push_back(item.second.first);
					} else {
						metadata += it.first + ":" + it.second + "\n";
					}
				}
			}
		}
		if (!g_abbv.empty()) {
			metadata += "G-Abbv:" + boost::algorithm::join(g_abbv, ",");
		}
	} else {
		for (auto it : req.header) {
			bool found = false;
			for (std::string s : http::skip_headers) {
				if (it.first == s) {
					found = true;
					break;
				}
			}
			if (!found) {
				std::function<std::string (const std::string&)> f = 
					[](const std::string& x) { 
						std::string s = x;
						boost::to_lower(s); 
						if (s.length() > 0) { 
							std::toupper(s[0]); 
						} 
						return s;
				};
				metadata += f(it.first) + ":" + it.second;
			}
		}
	}

	char *out = new char[metadata.size()];
	unsigned long out_len = 0;
	int r = compress((Bytef*)out, 
		&out_len, (Bytef*)metadata.c_str(), metadata.size());
	if (r != Z_OK) {
		delete [] out;
		return -1;
	}
	char* new_metadata = out + 2;
	out_len -= 6;

	if (common->GAE_OBFUSCATE == 1) {
		std::stringstream os;
		std::copy(base64_encode(new_metadata), 
			base64_encode(new_metadata+out_len), 
			bai::ostream_iterator<char>(os));
		std::string cookie = os.str();
		delete [] out;

		gae_req.header["Cookie"] = cookie;
		if (req.body_len == 0) {
			gae_req.method = "GET";
		} else {
			gae_req.method = "POST";
			gae_req.header["Cookie"] = cookie;
			gae_req.header["Content-Length"] = std::to_string(req.body_len);
			gae_req.body = req.body;
		}
		gae_req.body = req.body;
	} else {
		int len = 2+out_len+req.body_len;
		char *data = new char[len];
		unsigned short* l = (unsigned short*)data;
		*l = htons((unsigned short)out_len);
		memcpy(data+2, new_metadata, out_len);
		char *p = &(*req.body.get())[0];
		memcpy(data+2+out_len, p, req.body_len);
		gae_req.body.reset(new std::vector<char>(data, data+len));

		gae_req.method = "POST";
		gae_req.header["Content-Length"] = std::to_string(len);
	}
	gae_req.uri = common->GAE_FETCHSERVER;
	gae_req.proto = "HTTP/1.1";
	http::Url u;
	if (http::parse_url(gae_req.uri, u)) {
		gae_req.header["Host"] = u.host;
		gae_req.host = u.host;
	}
	return true;
}

int gae_request(http::ClientPtr client_ptr,
				const http::Request& req, 
				http::Respond& res,
				bool crlf) 
{
	// 发送request
	std::string msg = http::request_msg(req);
	std::vector<char> buf(msg.begin(), msg.end());
	// 发送request body
	char* boby = &(*req.body.get())[0];
	int r = client_ptr->Write(buf);
	if (r < 0) {
		return r;
	}

	// 读respond 并解析
	boost::asio::streambuf sbuf;
	r = client_ptr->ReadHeader(sbuf);
	if (r < 0) {
		return r;
	}
	const char* data = 
		boost::asio::buffer_cast<const char*>(sbuf.data());
	if (!http::parse_respond(data, res)) {
		return -1;
	}

	// 判断是否gae服务器问题
	auto common = Common::Get();
	if (res.status != http::status::ok) {
		if (res.status >= 400 && res.status <= 500) {
			common->GAE_CRLF = 0;
		}
		return -1;
	}

	// 解析真实的respond状态和header_len
	sbuf.consume(buf.size()); // 清空input 队列
	r = client_ptr->Read(4, sbuf);
	if (r < 0) {
		return r;
	}

	if (buf.size() < 4) {
		res.status = http::status::bad_gateway;
		return -1;
	}

	short *sh = 
		(short*)boost::asio::buffer_cast<const char*>(sbuf.data());
	int status = ::ntohs(sh[0]);
	int header_len = ::ntohs(sh[1]);

	res.status = (http::status::status_type)status;
	sbuf.consume(buf.size());

	// 读取header
	r = client_ptr->Read(header_len, sbuf);
	if (sbuf.size() < (size_t)header_len) {
		res.status = http::status::bad_gateway;
		return -1;
	}

	Bytef out_buf[8192]; // enough ?
	unsigned long out_len = 0;

	r = uncompress(out_buf, &out_len, 
		(Bytef*)boost::asio::buffer_cast<const char*>(sbuf.data()), sbuf.size());
	if (r != Z_OK) {
		return -1;
	}

	// 解析respond header
	char *hmsg = new char[out_len];
	memcpy(hmsg, out_buf, out_len);
	bool ok = http::parse_heaher(hmsg, res.header);
	delete [] hmsg;
	if (!ok) {
		return -1;
	}

	return 0;
}

std::string message_html(std::map<std::string, std::string>& param) {
    std::string MESSAGE_TEMPLATE = std::string("<html><head>")
    + "<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">"
    + "<title>{{ title }}</title>"
    + "<style><!--"
    + "body {font-family: arial,sans-serif}"
    + "div.nav {margin-top: 1ex}"
    + "div.nav A {font-size: 10pt; font-family: arial,sans-serif}"
    + "span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}"
    + "div.nav A,span.big {font-size: 12pt; color: #0000cc}"
    + "div.nav A {font-size: 10pt; color: black}"
    + "A.l:link {color: #6f6f6f}"
    + "A.u:link {color: green}"
    + "//--></style>"
    + "</head>"
    + "<body text=#000000 bgcolor=#ffffff>"
    + "<table border=0 cellpadding=2 cellspacing=0 width=100%>"
    + "<tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>"
    + "<tr><td> </td></tr></table>"
    + "<blockquote>"
    + "<H1>{{ banner }}</H1>"
    + "{{ detail }}"
    + "<p>"
    + "</blockquote>"
    + "<table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt=\"\" width=1 height=4></td></tr></table>"
    + "</body></html>";
    std::string& templ = MESSAGE_TEMPLATE;
	for (auto& it : param) {
		std::string s = "{{ " + it.first + " }}";
		templ = boost::algorithm::replace_all_copy(templ, s, it.second);
	}
    return templ;
}


int do_respond(const http::Respond& res, bool& crlf) {
	auto common = Common::Get();
	if (res.status > 400 && res.status < 500 || 
		(res.status == http::status::bad_gateway && common->GAE_PROFILE == "google_cn")) {
		common->GOOGLE_MODE = "https";
		common->GAE_FETCHSERVER = 
			common->GOOGLE_MODE + "://" + common->GAE_APPIDS[0] + ".appspot.com" + common->GAE_PATH + "?";

		return 0;
	}

	if (res.status == http::status::service_unavailable) {
		std::string appid = common->GAE_APPIDS.front();
		common->GAE_APPIDS.pop_front();
		common->GAE_APPIDS.push_back(appid);
		// 更新dns GOOGLE_HOSTS
		common->GAE_FETCHSERVER = 
			common->GOOGLE_MODE + 
			"://" + common->GAE_APPIDS[0] + ".appspot.com" + common->GAE_PATH + "?";
		return -1;
	}

	if (res.status > 400 && res.status < 405) {
		crlf = false;
		return -1;
	}
	
	return 0;
}


int GAEProxyHandler::do_gae_method() {
	// 处理request range 信息
	do_range(this->req_);

	auto local = this->conn_;

	// 读取request body 数据
	http::BodyPtr payload;
	int r = read_payload_and_compress();
	if (r != 0) {
		return -1;
	}

	bool first_send = false;

	auto common = Common::Get();
	// 和gae 服务端建立连接，发送封装的request，读取respond
	for (int i = 0; i < common->FETCHMAX_LOCAL; ++i) {
		// 封装为gae格式request
		http::Request req;
		if (!packet_gae_request(this->req_, req)) {
			return false;
		}
		bool need_crlf = common->GAE_CRLF == 1;
		if (req.url.scheme == "https") {
			need_crlf = false;
		}
		http::Respond res;
		r = this->http_.DoRequest(req, res, need_crlf);

		if (r < 0 && i == common->FETCHMAX_LOCAL - 1) {
			std::map<std::string, std::string> m;
			m["title"] = "502 URLFetch failed";
			m["banner"] = "Local URLFetch failed";

			local->Write("HTTP/1.0 502\r\n Content-Type: text/html\r\n\r\n" + message_html(m)); // all of msg is ascii, so not encode to utf-8
			return 0;
		} else {
			continue;
		}

		r = do_respond(res, need_crlf);
		if (r < 0) {
			continue;
		}

		if (res.status != 200 && r == common->FETCHMAX_LOCAL - 1) {
			local->Write(http::respond_msg(res));
			return 0;
		}

		if (!first_send) {
			if (res.status == 206) {
				// range fetch
				return 0;
			}
			if (res.header.find("Set-Cookie") != res.header.end()) {
			}
			local->Write(http::respond_msg(res));
			first_send = true;
		}

		int length = res.body_len;
		while (length > 0) {
			boost::asio::streambuf buf;
			r = res.body->Read(8192, buf);
			if (r != 0) {
				return r;
			}
			length -= buf.size();
			r = local->Write(buf);
			if (r != 0) {
				return r;
			}
		}
	}
	return 0;
}

int GAEProxyHandler::do_connect() {
	http::Respond res = http::status_respond(http::status::ok);
	int r = this->conn_->Write(http::respond_msg(res));
	if (r != 0) {
		return -1;
	}

	auto common = Common::Get();
	if (common->HOSTS_CONNECT_MATCH.size() > 0) {
		for (auto it : common->HOSTS_CONNECT_MATCH) {
			std::regex re(it.first);
			if (std::regex_search(req_.host, re)) {
				return this->fwd();
			}
		}
	}
	for (auto& site : common->GOOGLE_SITES) {
		if (req_.host.find(site) != std::string::npos) {
			bool found = false;
			for (auto& s : common->GOOGLE_WITHGAE) {
				if (req_.host.find(s) != std::string::npos) {
					found = true;
					break;
				}
			}
			if (!found) {
				return this->fwd();
			}
		}
	}
	return this->gae_fwd();
}

int GAEProxyHandler::fwd() {
	std::string host, port;
	http::parse_host_port(req_.url, host, port);

	http::Client* client = http_.CreateConnection(host, port);
	if (client == nullptr) {
		return -1;
	}

	std::thread thead([this, client]{
		while(1) {
			boost::asio::streambuf data;
			int r = client->Read(8192, data);
			if (r != 0) {
				return;
			}
			r = this->conn_->Write(data);
			if (r != 0) {
				return;
			}
		}
	});
	
	while(1) {
		boost::asio::streambuf data;
		int r = this->conn_->Read(8192, data);
		if (r != 0) {
			return r;
		}
		r = client->Write(data);
		if (r != 0) {
			return r;
		}
	}
	return 0;
}

int GAEProxyHandler::gae_fwd() {
	boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
	ctx.set_options(
		boost::asio::ssl::context::default_workarounds
		| boost::asio::ssl::context::no_sslv2
		| boost::asio::ssl::context::single_dh_use);

	auto cert = CertUtil::Get();
	std::string cert_file = cert->GetCert(req_.host);
	ctx.use_certificate_chain_file(cert_file);
	ctx.use_private_key_file(cert_file, boost::asio::ssl::context::pem);

	http::ConnPtr c((http::Conn*)this->conn_.get());
	http::SSLConnPtr ssl_conn(new http::SSLConn(c, ctx));
	http::HandlerPtr handler(this);

	return ssl_conn->Serve(handler);
}

int GAEProxyHandler::Handle(http::BaseConnPtr conn, const http::Request& req) {
	this->req_ = const_cast<http::Request&>(req);
	this->conn_ = conn;
	return this->do_method();
}

int GAEProxyHandler::Handle(http::BaseConnPtr conn) {
	this->conn_ = conn;
	std::string m = req_.method;
	if (req_.method == "CONNECT") {
		this->do_connect();
	}
	return this->do_method();
}