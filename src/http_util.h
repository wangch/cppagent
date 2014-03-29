//
// http_util.h
//

#ifndef _GOAGENT_HTTPUTIL_H_
#define _GOAGENT_HTTPUTIL_H_

#include <string>
#include <map>
#include <vector>

class HttpUtil {
public:
	HttpUtil();
	~HttpUtil();

	void Init();

private:
	std::map<std::string, std::string> msg_class_;
	std::string protocol_version_;
	std::vector<std::string> skip_headers_;
	std::map<std::string, std::pair<std::string, bool>> abbv_headers_;
	bool ssl_has_sni_;
	bool ssl_has_npn_;
	bool ssl_validate_;
	bool ssl_obfuscate;
	std::string ssl_ciphers_;

	int max_window_;
	int max_retry_;
	int max_timeout_;
	int tcp_connection_time_;
	int ssl_connection_time_;
	int crlf_;
	std::map<std::string, std::string> dns_;
	std::string proxy_;

};

#endif // _GOAGENT_HTTPUTIL_H_