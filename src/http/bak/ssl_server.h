//
// ssl_server.h  
//

#ifndef _GOAGENT_HTTP_SSLSERVER_H_
#define _GOAGENT_HTTP_SSLSERVER_H_

#include "request_handler.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace http {

	class ssl_conn;

	class ssl_server {
	public:
		ssl_server(boost::asio::io_service& io_service, 
			unsigned short port, 
			request_handler* handler,
			boost::asio::ssl::context& ctx);
		
		template<class ssl_conn>
		void start_accept(ssl_conn* conn);

		template<class ssl_conn>
		void handle_accept(ssl_conn* conn,
			const boost::system::error_code& error);

	private:
		boost::asio::io_service& io_service_;
		boost::asio::ip::tcp::acceptor acceptor_;
		boost::asio::ssl::context& context_;
		request_handler* handler_;
	};

} // namespace http

#endif // _GOAGENT_HTTP_SSLSERVER_H_