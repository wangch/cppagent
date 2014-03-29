//
// ssl_server.cc 
//

#include "ssl_server.h"
#include "request_parser.h"
#include "request_handler.h"
#include "request.h"
#include "reply.h"
#include <boost/bind.hpp>
#include <boost/array.hpp>

namespace http {

	typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

	ssl_server::ssl_server(
		boost::asio::io_service& io_service, 
		unsigned short port, 
		request_handler* handler,
		boost::asio::ssl::context& ctx) 
		: io_service_(io_service), 
		handler_(handler),
		acceptor_(io_service,
		boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
		context_(ctx) {
	}

	template<class ssl_conn>
	void ssl_server::start_accept(ssl_conn* conn) {
		ssl_conn* conn = new ssl_conn(io_service_, context_, handler_);
		acceptor_.async_accept(conn->socket(),
			boost::bind(&ssl_server::handle_accept, this, conn,
			boost::asio::placeholders::error));
	}

	template<class ssl_conn>
	void ssl_server::handle_accept(ssl_conn* conn,
		const boost::system::error_code& error) {
		if (!error) {
			conn->start();
		} else {
			delete conn;
		}

		start_accept();
	}




	/*
	int main(int argc, char* argv[])
	{
	try
	{
	if (argc != 3)
	{
	std::cerr << "Usage: client <host> <port>\n";
	return 1;
	}

	boost::asio::io_service io_service;

	boost::asio::ip::tcp::resolver resolver(io_service);
	boost::asio::ip::tcp::resolver::query query(argv[1], argv[2]);
	boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);

	boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
	ctx.load_verify_file("ca.pem");

	client c(io_service, ctx, iterator);

	io_service.run();
	}
	catch (std::exception& e)
	{
	std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
	}
	*/

	/*
	int main(int argc, char* argv[])
	{
	try
	{
	if (argc != 2)
	{
	std::cerr << "Usage: ssl_server <port>\n";
	return 1;
	}

	boost::asio::io_service io_service;

	using namespace std; // For atoi.
	ssl_server s(io_service, atoi(argv[1]));

	io_service.run();
	}
	catch (std::exception& e)
	{
	std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
	}
	*/


} // namespace http