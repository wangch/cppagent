//
// ssl_client.cc 
//

#include "ssl_client.h"
#include <iostream>
#include <boost/bind.hpp>


namespace http {

ssl_client::ssl_client(boost::asio::io_service& io_service,
	   boost::asio::ssl::context& context,
	   boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	   : socket_(io_service, context)
{
	socket_.set_verify_mode(boost::asio::ssl::verify_peer);
	socket_.set_verify_callback(
		boost::bind(&ssl_client::verify_certificate, this, _1, _2));

	boost::asio::async_connect(socket_.lowest_layer(), endpoint_iterator,
		boost::bind(&ssl_client::handle_connect, this,
		boost::asio::placeholders::error));
}

bool ssl_client::verify_certificate(bool preverified,
						boost::asio::ssl::verify_context& ctx)
{
	// The verify callback can be used to check whether the certificate that is
	// being presented is valid for the peer. For example, RFC 2818 describes
	// the steps involved in doing this for HTTPS. Consult the OpenSSL
	// documentation for more details. Note that the callback is called once
	// for each certificate in the certificate chain, starting from the root
	// certificate authority.

	// In this example we will simply print the certificate's subject name.
	char subject_name[256];
	X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
	X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
	std::cout << "Verifying " << subject_name << "\n";

	return preverified;
}

void ssl_client::handle_connect(const boost::system::error_code& error)
{
	if (!error)
	{
		socket_.async_handshake(boost::asio::ssl::stream_base::client,
			boost::bind(&ssl_client::handle_handshake, this,
			boost::asio::placeholders::error));
	}
	else
	{
		std::cout << "Connect failed: " << error.message() << "\n";
	}
}

void ssl_client::handle_handshake(const boost::system::error_code& error)
{
	if (!error)
	{
		std::cout << "Enter message: ";
		std::cin.getline(request_, max_length);
		size_t request_length = strlen(request_);

		boost::asio::async_write(socket_,
			boost::asio::buffer(request_, request_length),
			boost::bind(&ssl_client::handle_write, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
	}
	else
	{
		std::cout << "Handshake failed: " << error.message() << "\n";
	}
}

void ssl_client::handle_write(const boost::system::error_code& error,
				  size_t bytes_transferred)
{
	if (!error)
	{
		boost::asio::async_read(socket_,
			boost::asio::buffer(reply_, bytes_transferred),
			boost::bind(&ssl_client::handle_read, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
	}
	else
	{
		std::cout << "Write failed: " << error.message() << "\n";
	}
}

void ssl_client::handle_read(const boost::system::error_code& error,
				 size_t bytes_transferred)
{
	if (!error)
	{
		std::cout << "Reply: ";
		std::cout.write(reply_, bytes_transferred);
		std::cout << "\n";
	}
	else
	{
		std::cout << "Read failed: " << error.message() << "\n";
	}
}

} // namespace http
