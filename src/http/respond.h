//
// respond.h
// ~~~~~~~~~~~
//


#ifndef HTTP_RESPOND_H_
#define HTTP_RESPOND_H_

#include "util.h"
#include <boost/algorithm/string.hpp>
#include <regex>

namespace http {

	class BaseConn;
	namespace status {
		enum status_type
		{
			ok = 200,
			created = 201,
			accepted = 202,
			no_content = 204,
			partial_content = 206,
			multiple_choices = 300,
			moved_permanently = 301,
			moved_temporarily = 302,
			not_modified = 304,
			bad_request = 400,
			unauthorized = 401,
			forbidden = 403,
			not_found = 404,
			internal_server_error = 500,
			not_implemented = 501,
			bad_gateway = 502,
			service_unavailable = 503
		};

		namespace status_string {
			const std::string ok =
				"HTTP/1.0 200 OK\r\n";
			const std::string created =
				"HTTP/1.0 201 Created\r\n";
			const std::string accepted =
				"HTTP/1.0 202 Accepted\r\n";
			const std::string no_content =
				"HTTP/1.0 204 No Content\r\n";
			const std::string partial_content =
				"HTTP/1.0 206 Partial Content\r\n";
			const std::string multiple_choices =
				"HTTP/1.0 300 Multiple Choices\r\n";
			const std::string moved_permanently =
				"HTTP/1.0 301 Moved Permanently\r\n";
			const std::string moved_temporarily =
				"HTTP/1.0 302 Moved Temporarily\r\n";
			const std::string not_modified =
				"HTTP/1.0 304 Not Modified\r\n";
			const std::string bad_request =
				"HTTP/1.0 400 Bad Request\r\n";
			const std::string unauthorized =
				"HTTP/1.0 401 Unauthorized\r\n";
			const std::string forbidden =
				"HTTP/1.0 403 Forbidden\r\n";
			const std::string not_found =
				"HTTP/1.0 404 Not Found\r\n";
			const std::string internal_server_error =
				"HTTP/1.0 500 Internal Server Error\r\n";
			const std::string not_implemented =
				"HTTP/1.0 501 Not Implemented\r\n";
			const std::string bad_gateway =
				"HTTP/1.0 502 Bad Gateway\r\n";
			const std::string service_unavailable =
				"HTTP/1.0 503 Service Unavailable\r\n";
		}

		inline std::string status_code_string(status_type status) {
			switch (status)
			{
			case status::ok:
				return status_string::ok;
			case status::created:
				return status_string::created;
			case status::accepted:
				return status_string::accepted;
			case status::no_content:
				return status_string::no_content;
			case status::partial_content:
				return status_string::partial_content;
			case status::multiple_choices:
				return status_string::multiple_choices;
			case status::moved_permanently:
				return status_string::moved_permanently;
			case status::moved_temporarily:
				return status_string::moved_temporarily;
			case status::not_modified:
				return status_string::not_modified;
			case status::bad_request:
				return status_string::bad_request;
			case status::unauthorized:
				return status_string::unauthorized;
			case status::forbidden:
				return status_string::forbidden;
			case status::not_found:
				return status_string::not_found;
			case status::internal_server_error:
				return status_string::internal_server_error;
			case status::not_implemented:
				return status_string::not_implemented;
			case status::bad_gateway:
				return status_string::bad_gateway;
			case status::service_unavailable:
				return status_string::service_unavailable;
			default:
				return status_string::internal_server_error;
			}
		}


		namespace status_html {

			const char ok[] = "";
			const char created[] =
				"<html>"
				"<head><title>Created</title></head>"
				"<body><h1>201 Created</h1></body>"
				"</html>";
			const char accepted[] =
				"<html>"
				"<head><title>Accepted</title></head>"
				"<body><h1>202 Accepted</h1></body>"
				"</html>";
			const char no_content[] =
				"<html>"
				"<head><title>No Content</title></head>"
				"<body><h1>204 Content</h1></body>"
				"</html>";
			const char partial_content[] =
				"<html>"
				"<head><title>Partial Content</title></head>"
				"<body><h1>206 Content</h1></body>"
				"</html>";
			const char multiple_choices[] =
				"<html>"
				"<head><title>Multiple Choices</title></head>"
				"<body><h1>300 Multiple Choices</h1></body>"
				"</html>";
			const char moved_permanently[] =
				"<html>"
				"<head><title>Moved Permanently</title></head>"
				"<body><h1>301 Moved Permanently</h1></body>"
				"</html>";
			const char moved_temporarily[] =
				"<html>"
				"<head><title>Moved Temporarily</title></head>"
				"<body><h1>302 Moved Temporarily</h1></body>"
				"</html>";
			const char not_modified[] =
				"<html>"
				"<head><title>Not Modified</title></head>"
				"<body><h1>304 Not Modified</h1></body>"
				"</html>";
			const char bad_request[] =
				"<html>"
				"<head><title>Bad Request</title></head>"
				"<body><h1>400 Bad Request</h1></body>"
				"</html>";
			const char unauthorized[] =
				"<html>"
				"<head><title>Unauthorized</title></head>"
				"<body><h1>401 Unauthorized</h1></body>"
				"</html>";
			const char forbidden[] =
				"<html>"
				"<head><title>Forbidden</title></head>"
				"<body><h1>403 Forbidden</h1></body>"
				"</html>";
			const char not_found[] =
				"<html>"
				"<head><title>Not Found</title></head>"
				"<body><h1>404 Not Found</h1></body>"
				"</html>";
			const char internal_server_error[] =
				"<html>"
				"<head><title>Internal Server Error</title></head>"
				"<body><h1>500 Internal Server Error</h1></body>"
				"</html>";
			const char not_implemented[] =
				"<html>"
				"<head><title>Not Implemented</title></head>"
				"<body><h1>501 Not Implemented</h1></body>"
				"</html>";
			const char bad_gateway[] =
				"<html>"
				"<head><title>Bad Gateway</title></head>"
				"<body><h1>502 Bad Gateway</h1></body>"
				"</html>";
			const char service_unavailable[] =
				"<html>"
				"<head><title>Service Unavailable</title></head>"
				"<body><h1>503 Service Unavailable</h1></body>"
				"</html>";

			inline std::string to_string(status::status_type status) {
				switch (status)
				{
				case status::ok:
					return ok;
				case status::created:
					return created;
				case status::accepted:
					return accepted;
				case status::no_content:
					return no_content;
				case status::partial_content:
					return partial_content;
				case status::multiple_choices:
					return multiple_choices;
				case status::moved_permanently:
					return moved_permanently;
				case status::moved_temporarily:
					return moved_temporarily;
				case status::not_modified:
					return not_modified;
				case status::bad_request:
					return bad_request;
				case status::unauthorized:
					return unauthorized;
				case status::forbidden:
					return forbidden;
				case status::not_found:
					return not_found;
				case status::internal_server_error:
					return internal_server_error;
				case status::not_implemented:
					return not_implemented;
				case status::bad_gateway:
					return bad_gateway;
				case status::service_unavailable:
					return service_unavailable;
				default:
					return internal_server_error;
				}
			}

		} // namespace status_html
	} // namesapce status

	struct Request;

	struct Respond {
		Request* request;
		status::status_type status;
		Header header;
		int body_len;
		ClientPtr body;
		Respond() : body_len(0), body(0) {}
	};

	inline bool parse_respond(const std::string& data, Respond& res) {
		std::vector<std::string> v;
		boost::split(v, data, boost::is_any_of(CRLF), boost::token_compress_on);
		if (v.size() < 1) {
			return false;
		}

		std::string& req_line = v[0];
		std::vector<std::string> v1;
		boost::split(v1, req_line, boost::is_any_of(" "), boost::token_compress_on);
		if (v1.size() < 2) {
			return false;
		}
		std::string status = boost::trim_copy(v[1]);
		res.status = (status::status_type)std::atoi(status.c_str());

		for (size_t i = 1; i < v.size(); ++i) {
			std::string& line = v[i];
			std::vector<std::string> v2;
			boost::split(v2, line, boost::is_any_of(":"), boost::token_compress_on);
			if (v2.size() < 2) {
				continue;
			}
			res.header.insert(std::make_pair(v2[0], v2[1]));
		}

		// 获取body 长度
		int begin, end, length;
		int content_length = 0;
		if (res.header.find("Content-Length") != res.header.end()) {
			content_length = std::atoi(res.header["Content-Length"].c_str());
		}

		std::regex re("bytes (\\d+)-(\\d+)/(\\d+)");
		std::string content_range = res.header["Content-Range"];
		std::smatch m;
		if (std::regex_search(content_range, m, re)) {
			if (m.size() < 3) {
				return false;
			}
			begin = std::atoi(m[0].str().c_str());
			end = std::atoi(m[1].str().c_str());
			length = std::atoi(m[1].str().c_str());
		} else {
			begin = 0;
			end = length = content_length ;
		}
		res.body_len = length;
		return true;
	}

	inline std::string respond_msg(const Respond& res) {
		std::string r = status::status_code_string(res.status);
		r += header_string(res.header);
		return r;
	}


	inline Respond status_respond(status::status_type status) {
		Respond res;
		res.status = status;
		//std::string body(status::status_html::to_string(status));
		//res.body = new StringBuf(body);
		//res.header["Content-Length"] = std::to_string(body.size());
		//res.header["Content-Type"] = "text/html";
		return res;
	}

	//int respond_buf(const Respond& res, boost::asio::streambuf& buf) {
	//	return string_buf(respond_msg(res), buf);
	//}


} // namespace http

#endif // HTTP_RESPOND_H_