//
// request.h
// ~~~~~~~~~~~
//


#ifndef HTTP_REQUEST_H_
#define HTTP_REQUEST_H_

#include "util.h"
#include <vector>
#include <utility>


namespace http {

	struct Request {
		std::string method;
		std::string uri;
		std::string proto;
		Url url;
		std::string host;
		Header header;
		int body_len;
		BodyPtr body;
		Request() : body_len(0) {}
	};

	inline bool parse_request_line(const std::string& line, std::vector<std::string> &v) {
		std::string& req_line = v[0];
		std::vector<std::string> v1;
		boost::split(v1, req_line, boost::is_any_of(" "), boost::token_compress_on);
		if (v1.size() < 3) {
			return false;
		}
		boost::to_upper(v[0]);
		return true;
	}

	inline bool parse_url(const std::string& rawurl, Url& url) {
		if (rawurl.empty()) {
			return false;
		}
		size_t pos = rawurl.find(":");
		if (pos == std::string::npos) {
			return false;
		}

		url.scheme = rawurl.substr(0, pos);
		pos = rawurl.find_first_not_of("/");
		std::string rest(rawurl.substr(pos));
		std::vector<std::string> v;
		boost::split(v, rest, boost::is_any_of("?"), boost::token_compress_on);
		rest = v[0];
		if (v.size() > 1) {
			url.query = v[1];
		}

		url.rawurl = rawurl;

		if (!url.host.empty()) {
			return true;
		}

		pos = rest.find("/");
		if (pos != std::string::npos) {
			url.host = rest.substr(0, pos);
			url.path = rest.substr(pos);
		} else {
			url.host = rest;
		}

		return true;
	}

	inline bool parse_request(const std::string& data, Request& req) {
		std::vector<std::string> v;
		boost::split(v, data, boost::is_any_of(CRLF), boost::token_compress_on);
		if (v.size() < 1) {
			return false;
		}

		std::vector<std::string> line;
		if (!parse_request_line(v[0], line)) {
			return false;
		}
		req.method = line[0];
		req.uri = line[1];
		req.proto = line[2];

		for (size_t i = 1; i < v.size(); ++i) {
			std::string& line = v[i];
			std::vector<std::string> v2;
			boost::split(v2, line, boost::is_any_of(":"), boost::token_compress_on);
			if (v2.size() < 2) {
				continue;
			}
			req.header.insert(std::make_pair(v2[0], v2[1]));
		}
		bool host_in_header = req.header.find("Host") != req.header.end();
		std::string url = req.uri;
		if (req.uri[0] == '/') {
			if (!host_in_header) {
				return false;
			}				
			url = "http://" + req.host + req.uri;
			req.url.host = req.host;
		} 
		if(!parse_url(url, req.url)) {
			return false;
		}
		return true;
	}

	inline std::string request_msg(const Request& req) {
		std::string r = req.method + " " + req.uri + " " + req.proto + CRLF;
		r += header_string(req.header);
		return r;
	}

} // namespace http

#endif // HTTP_REQUEST_H_
