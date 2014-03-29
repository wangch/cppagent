//
// conn.h
// ~~~~~~~~~~~~~~
//

#ifndef HTTP_CONNECTION_H_
#define HTTP_CONNECTION_H_

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio/ssl.hpp>
#include <utility>


namespace http {
	typedef boost::asio::ip::tcp::socket socket;
	typedef boost::asio::ssl::stream<socket&> ssl_socket;
	typedef boost::asio::ssl::context ssl_context;

	struct Request;
	class RequestHandler;
	typedef std::shared_ptr<RequestHandler> HandlerPtr;

	class BaseConn : public boost::noncopyable {
	public:
		BaseConn() {}
		virtual ~BaseConn() {}
		virtual int read_header(boost::asio::streambuf& buf) {
			return -1;
		}

		virtual int ReadRequest(Request& req) {
			return -1;
		}
		virtual int Read(int rdlen, boost::asio::streambuf& buf) {
			return -1;
		}
		virtual int Write(boost::asio::streambuf& buf) {
			return -1;
		}
		virtual int Write(const std::vector<char>& buf) {
			return -1;
		}
		virtual int Write(const std::string& buf) {
			return -1;
		}

		int serve(HandlerPtr handler, bool join = false);
		virtual int Serve(HandlerPtr handler) {
			return -1;
		}
	};

	class Conn : public BaseConn {
		socket socket_;
		virtual int read_header(boost::asio::streambuf& buf);
	public:
		Conn(boost::asio::io_service& io_service);
		virtual ~Conn();
		virtual int Read(int rdlen, boost::asio::streambuf& buf);
		virtual int Write(boost::asio::streambuf& buf);
		virtual int Write(const std::vector<char>& buf);
		virtual int Write(const std::string& buf);
		int ReadRequest(Request& req);
		socket& Socket() {
			return socket_;
		}
		virtual int Serve(HandlerPtr handler);
	};

	typedef boost::asio::ssl::stream_base::handshake_type handshake_type;
	typedef std::shared_ptr<Conn> ConnPtr;
	typedef std::shared_ptr<BaseConn> BaseConnPtr;

	class SSLConn : public BaseConn {
		ssl_socket socket_;
		ConnPtr c_;
		virtual int read_header(boost::asio::streambuf& buf);
	public:
		SSLConn(boost::asio::io_service& ios, ssl_context& ctx);
		SSLConn(ConnPtr c, ssl_context& ctx);
		virtual ~SSLConn();
		ssl_socket& Socket() {
			return socket_;
		}
		int Handshake(handshake_type type = handshake_type::server);
		virtual int Read(int rdlen, boost::asio::streambuf& buf);
		virtual int Write(boost::asio::streambuf& buf);
		virtual int Write(const std::vector<char>& buf);
		virtual int Write(const std::string& buf);
		virtual int Serve(HandlerPtr handler);
	};

	typedef std::shared_ptr<SSLConn> SSLConnPtr;

	class RequestHandler {
	public:
		virtual ~RequestHandler(){}
		virtual int Handle(BaseConnPtr conn, const Request& req) { return -1; }
	};

	class Client {
		BaseConnPtr c_;
	public:
		Client(BaseConnPtr c) : c_(c) {}
		Client() {}
		virtual ~Client() {}
		virtual int Connect(boost::asio::io_service& ios, const std::string& host, const std::string& svc);
		BaseConnPtr& conn() {
			return c_;
		}

		int Read(int len, boost::asio::streambuf& buf);
		int Write(boost::asio::streambuf& buf);
		int Write(const std::vector<char>& buf);
		int Write(const std::string& buf);
		int ReadHeader(boost::asio::streambuf& buf);
	};

	typedef std::shared_ptr<Client> ClientPtr;

	class SSLClient : public Client {
	public:
		SSLClient(BaseConnPtr c) : Client(c) {}
		virtual ~SSLClient() {}
		virtual int Connect(boost::asio::io_service& ios, const std::string& host, const std::string& svc);
	};

} // namespace http

#endif // HTTP_CONNECTION_H_
