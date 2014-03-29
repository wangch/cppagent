//
// ssl_client.h  
//

#ifndef _GOAGENT_HTTP_SSLCLIENT_H_
#define _GOAGENT_HTTP_SSLCLIENT_H_

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>


namespace http {

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

class ssl_client {
public:
	ssl_client(boost::asio::io_service& io_service,
		boost::asio::ssl::context& context,
		boost::asio::ip::tcp::resolver::iterator endpoint_iterator);

	bool verify_certificate(bool preverified,
		boost::asio::ssl::verify_context& ctx);

	void handle_connect(const boost::system::error_code& error);

	void handle_handshake(const boost::system::error_code& error);
	
	void handle_write(const boost::system::error_code& error,
		size_t bytes_transferred);

	void handle_read(const boost::system::error_code& error,
		size_t bytes_transferred);

private:
	ssl_socket socket_;
	enum { max_length = 8192 };
	char request_[max_length];
	char reply_[max_length];
};

} // namespace http

#endif // _GOAGENT_HTTP_SSLCLIENT_H_