//
// http_util.cc
//

#include "http_util.h"
#include "conn.h"
#include "request.h"
#include "respond.h"
#include <cstdlib>
#include <iostream>
#include <ctime>

namespace http {

	const std::string ssl_ciphers[] = {
		"ECDHE-ECDSA-AES256-SHA",
		"ECDHE-RSA-AES256-SHA",
		"DHE-RSA-CAMELLIA256-SHA",
		"DHE-DSS-CAMELLIA256-SHA",
		"DHE-RSA-AES256-SHA",
		"DHE-DSS-AES256-SHA",
		"ECDH-RSA-AES256-SHA",
		"ECDH-ECDSA-AES256-SHA",
		"CAMELLIA256-SHA",
		"AES256-SHA",
		"ECDHE-ECDSA-RC4-SHA",
		"ECDHE-ECDSA-AES128-SHA",
		"ECDHE-RSA-RC4-SHA",
		"ECDHE-RSA-AES128-SHA",
		"DHE-RSA-CAMELLIA128-SHA",
		"DHE-DSS-CAMELLIA128-SHA",
		"DHE-RSA-AES128-SHA",
		"DHE-DSS-AES128-SHA",
		"ECDH-RSA-RC4-SHA",
		"ECDH-RSA-AES128-SHA",
		"ECDH-ECDSA-RC4-SHA",
		"ECDH-ECDSA-AES128-SHA",
		"SEED-SHA",
		"CAMELLIA128-SHA",
		"RC4-SHA",
		"RC4-MD5",
		"AES128-SHA",
		"ECDHE-ECDSA-DES-CBC3-SHA",
		"ECDHE-RSA-DES-CBC3-SHA",
		"EDH-RSA-DES-CBC3-SHA",
		"EDH-DSS-DES-CBC3-SHA",
		"ECDH-RSA-DES-CBC3-SHA",
		"ECDH-ECDSA-DES-CBC3-SHA",
		"DES-CBC3-SHA",
		"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
	};

	std::map<std::string, PF> abbv_headers = init_abbv_headers();

	HttpUtil::HttpUtil(boost::asio::io_service& ios) :
		ios_(ios), 
		ctx_(boost::asio::ssl::context::sslv23) {
	}

	HttpUtil::~HttpUtil() {
	}

	void HttpUtil::Init(int max_window, bool ssl_validata, bool ssl_obfuscate, const std::string& proxy) {
		this->max_window_ = max_window;
		this->proxy_ = proxy;
		this->ssl_validate_ = ssl_validata;
		this->ssl_obfuscate_ = ssl_obfuscate;
		if (ssl_validata) {
			this->ctx_.set_verify_mode(boost::asio::ssl::verify_fail_if_no_peer_cert);
			this->ctx_.load_verify_file("caert.pem");
		}
	}

	Client* HttpUtil::CreateConnection(const std::string& host, const std::string& port) {
		Client* c = new Client();
		int r = c->Connect(this->ios_, host, port);
		if (r != 0) {
			delete c;
			return nullptr;
		}
		return c;
	}

	Client* HttpUtil::CreateSSLConnection(const std::string& host, const std::string& port) {
		SSLConn* sc = new SSLConn(this->ios_, this->ctx_);
		if (this->ssl_obfuscate_) {
			std::vector<std::string> v;
			::srand((unsigned int)time(0));
			for (auto& s : ssl_ciphers) {
				if (::rand() % 10 > 5) {
					v.push_back(s);
				}
			}
			SSL_set_cipher_list(sc->Socket().native_handle(), boost::algorithm::join(v, ":").c_str());
		}

		BaseConnPtr bcp(sc);
		SSLClient* client = new SSLClient(bcp);
		int r = client->Connect(this->ios_, host, port);
		if (r != 0) {
			delete client;
			return nullptr;
		}
		return client;
	}

	int read_respond(ClientPtr c, Respond& res) {
		boost::asio::streambuf buf;
		int r = c->ReadHeader(buf);
		if (r != 0) {
			return 0;
		}
		std::ostream os(&buf);
		std::string resmsg;
		os << resmsg;
		if(!parse_respond(resmsg, res)) {
			return -1;
		}
		return 0;
	}

	void parse_host_port(const http::Url& u, std::string& host, std::string& port) {
		int pos = u.host.find(":");
		if (pos == std::string::npos) {
			host = u.host;
			if (u.scheme == "https") {
				port = "443";
			} else {
				port = "80";
			}
		} else {
			host = u.host.substr(0, pos);
			port = u.host.substr(pos+1);
		}
	}

	int HttpUtil::DoRequest(const Request& req, Respond& res, bool crlf) {
		Client* c = nullptr;
		std::string host, port;
		parse_host_port(req.url, host, port);

		if (req.url.scheme == "https") {
			c = CreateSSLConnection(host, port);
		} else {
			c = CreateConnection(host, port);
		}
		if (c == nullptr) {
			return -1;
		}
		
		ClientPtr client(c);
		Request& request = const_cast<Request&>(req);

		if (request.header.find("Host") != request.header.end()) {
			request.header.erase("Host");
		}

		std::string reqmsg(request.method + " " + request.uri + " " + request.proto + CRLF);
		for (auto& s : request.header) {
			bool found = false;
			for (auto& x : skip_headers) {
				if (x == s.first) {
					found = true;
					break;
				}
			}
			if (!found) {
				reqmsg += s.first + ": " + s.second;
			}
		}
		if (crlf) {
			reqmsg = "GET / HTTP/1.1\r\n\r\n\r\n" + reqmsg;
		}

		int r = client->Write(reqmsg);
		if (r != 0) {
			return -1;
		}
		std::vector<char>* v = request.body.get();
		r = client->Write(*v);
		if (r != 0) {
			return - 1;
		}

		if (crlf) {
			Respond rr;
			r = read_respond(client, rr);
			if (r != 0) {
				return -1;
			}
			boost::asio::streambuf buf;
			r = client->Read(rr.body_len, buf);
			if (r != 0) {
				return -1;
			}
		}

		if (read_respond(client, res) != 0) {
			return -1;
		}
		ClientPtr cp(client);
		res.body = cp;
		return 0;
	}

} // namespace http

