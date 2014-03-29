//
// http_util.h
//


#ifndef HTTP_HTTPUTIL_H_
#define HTTP_HTTPUTIL_H_

#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/asio/ssl.hpp>
#include <string>

namespace http {

	const std::string protocol_version = "HTTP/1.1";
	const std::string skip_headers[] = {
		"Vary", 
		"Via", 
		"X-Forwarded-For", 
		"Proxy-Authorization", 
		"Proxy-Connection", 
		"Upgrade", 
		"X-Chrome-Variations",
		"Connection", 
		"Cache-Control"
	};

	typedef	std::function<bool(const std::string& x)> F;
	typedef std::pair<std::string, F> PF;

	inline std::map<std::string, PF> init_abbv_headers() {
		std::map<std::string, PF> m;
		m["Accept"] = std::make_pair("A", [](const std::string& x) { 
			return x.find("*/*") != std::string::npos; 
		});
		m["Accept-Charset"] = std::make_pair("AC", [](const std::string& x) { 
			return boost::ends_with(x, "UTF-8,"); 
		});
		m["Accept-Language"] = std::make_pair("AL", [](const std::string& x) { 
			return boost::ends_with(x, "zh-CN,"); 
		});
		m["Accept-Encoding"] = std::make_pair("AE", [](const std::string& x) { 
			return boost::ends_with(x, "gzip,"); 
		});
		return m;
	}

	extern std::map<std::string, PF> abbv_headers;

	class Client;
	struct Request;
	struct Respond;
	struct Url;

	void parse_host_port(const Url& u, std::string& host, std::string& port);

	class HttpUtil : boost::noncopyable {
		boost::asio::io_service& ios_;
		boost::asio::ssl::context ctx_;
		int max_window_;
		bool ssl_validate_;
		bool ssl_obfuscate_;
		std::string proxy_; // ip:port
	public:
		HttpUtil(boost::asio::io_service& ios);
		~HttpUtil();

		void Init(int max_window, bool ssl_validata = false, bool ssl_obfuscate = false, const std::string& = "");

		Client* CreateConnection(const std::string& host, const std::string& port);
		Client* CreateSSLConnection(const std::string& host, const std::string& port);
		int DoRequest(const Request& req, Respond& res, bool crlf = false);
	};

} // namespace httpp

#endif // HTTP_HTTPUTIL_H_

