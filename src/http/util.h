//
// util.h
// ~~~~~~~~~~~
//


#ifndef HTTP_UTIL_H_
#define HTTP_UTIL_H_

#include <string>
#include <vector>
#include <map>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

namespace http {

	typedef std::shared_ptr<std::vector<char>> BodyPtr;

	struct Url {
		std::string scheme;
		std::string host;
		std::string path;
		std::string query;
		std::string fregment;
		std::string rawurl;
	};

	const std::string CRLF = "\r\n";

	typedef std::map<std::string, std::string> Header;

	inline std::string header_string(const Header& header) {
		std::string h;
		for (auto it = header.begin(); it != header.end(); ++it) {
			h += it->first + ": " + it->second + CRLF;
		}
		h += CRLF;
		return h;
	}

	inline bool parse_heaher(const std::string& data, Header& header) {
		std::vector<std::string> v;
		boost::split(v, data, boost::is_any_of(CRLF), boost::token_compress_on);
		if (v.size() < 1) {
			return false;
		}
		for (std::string& line : v) {
			std::vector<std::string> v2;
			boost::split(v2, line, boost::is_any_of(":"), boost::token_compress_on);
			if (v2.size() < 2) {
				continue;
			}
			header.insert(std::make_pair(v2[0], v2[1]));
		}
		return true;
	}

} // namespace http

#endif // HTTP_UTIL_H_