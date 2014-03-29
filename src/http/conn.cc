//
// conn.cc
// ~~~~~~~~~~~~~~
//


#include "conn.h"
#include "request.h"
#include <thread>

namespace http {

	Conn::Conn(boost::asio::io_service& io_service) : socket_(io_service) {

	}

	Conn::~Conn() {

	}

	enum {
		BAD_REQUEST = -4587
	};

	int Conn::read_header(boost::asio::streambuf& buf) {
		boost::system::error_code error;
		size_t len = boost::asio::read_until(socket_, buf, "\r\n\r\n", error);
		buf.commit(len);
		return error.value();
	}

	int SSLConn::read_header(boost::asio::streambuf& buf) {
		boost::system::error_code error;
		size_t len = boost::asio::read_until(socket_, buf, "\r\n\r\n", error);
		buf.commit(len);
		return error.value();
	}

	int Conn::ReadRequest(Request& req) {
		boost::asio::streambuf buf;
		int err = this->read_header(buf);
		std::istream is(&buf);
		int len = buf.size();
		char* s = new char[len];
		is.read(s, len);
		std::string data(s);
		if (err != boost::system::errc::success) {
			delete [] s;
			return err;
		}
		delete [] s;
		bool r = parse_request(data, req);
		if (!r) {
			return BAD_REQUEST;
		}
		return 0;
	}

	int Conn::Read(int rdlen, boost::asio::streambuf& buf) {
		boost::system::error_code error;
		size_t len = boost::asio::read(socket_, buf, boost::asio::transfer_at_least(rdlen), error);
		buf.commit(len);
		return error.value();
	}

	int Conn::Write(boost::asio::streambuf& buf) {
		boost::system::error_code error;
		size_t len = boost::asio::write(socket_, buf, error);
		buf.consume(len);
		return error.value();
	}

	int Conn::Write(const std::vector<char>& buf) {
		boost::system::error_code error;
		boost::asio::write(socket_, boost::asio::buffer(buf), error);
		return error.value();
	}

	int Conn::Write(const std::string& buf) {
		std::vector<char> v(buf.begin(), buf.end());
		return this->Write(buf);
	}

	int BaseConn::serve(HandlerPtr handler, bool join) {
		std::thread thr([this, handler]{
			while(1) {
				Request req;
				int r = this->ReadRequest(req);
				if (r != 0) {
					if (r == BAD_REQUEST) {
						const char *bad_res_msg = "HTTP/1.0 400 Bad Request\r\n";
						this->Write(bad_res_msg);
					} else {
						break;
					}
				}
				BaseConnPtr c(this);
				handler->Handle(c, req);
			}
		});
		if (join) {
			thr.join();
		} else {
			thr.detach();
		}
		return 0;
	}

	SSLConn::SSLConn(boost::asio::io_service& ios, ssl_context& ctx) 
		: c_(new Conn(ios)), socket_(c_->Socket(), ctx) {
	}

	SSLConn::SSLConn(ConnPtr c, ssl_context& ctx) 
		: c_(c), socket_(c_->Socket(), ctx) {
	}

	SSLConn::~SSLConn() {

	}

	int SSLConn::Read(int rdlen, boost::asio::streambuf& buf) {
		boost::system::error_code error;
		size_t len = boost::asio::read(socket_, buf, boost::asio::transfer_at_least(rdlen), error);
		buf.commit(len);
		return error.value();
	}

	int SSLConn::Handshake(handshake_type type) {
		boost::system::error_code error;
		socket_.handshake(type, error);
		if (error != boost::system::errc::success) {
			return -1;
		}
		return 0;
	}

	int SSLConn::Write(boost::asio::streambuf& buf) {
		boost::system::error_code error;
		size_t len = boost::asio::write(socket_, buf, error);
		buf.consume(len);
		return error.value();
	}

	int SSLConn::Write(const std::vector<char>& buf) {
		boost::system::error_code error;
		boost::asio::write(socket_, boost::asio::buffer(buf), error);
		return error.value();
	}

	int SSLConn::Write(const std::string& buf) {
		std::vector<char> v(buf.begin(), buf.end());
		return this->Write(buf);
	}

	int Conn::Serve(HandlerPtr handler) {
		return this->serve(handler, false);
	}

	int SSLConn::Serve(HandlerPtr handler) {
		int r = this->Handshake();
		if (r != 0) {
			return r;
		}
		return this->serve(handler, true);
	}

	int Client::Connect(boost::asio::io_service& ios, const std::string& host, const std::string& port) {
		boost::asio::ip::tcp::resolver resolver(ios);
		boost::asio::ip::tcp::resolver::query query(host, port);
		boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
		boost::system::error_code err;
		Conn* c = new Conn(ios);
		this->c_.reset(c);
		boost::asio::connect(c->Socket(), endpoint_iterator, err);
		if (err != boost::system::errc::success) {
			return -1;
		}
		return 0;
	}

	int SSLClient::Connect(boost::asio::io_service& ios, const std::string& host, const std::string& port) {
		int r = Client::Connect(ios, host, port);
		if (r != 0) {
			return -1;
		}
		ssl_context ctx(boost::asio::ssl::context::sslv23);
		SSLConn* ssl_c = new SSLConn(ios, ctx);
		this->conn().reset(ssl_c);
		return ssl_c->Handshake(handshake_type::client);
	}

	int Client::Read(int len, boost::asio::streambuf& buf) {
		return this->conn()->Read(len, buf);
	}

	int Client::Write(boost::asio::streambuf& buf) {
		return this->conn()->Write(buf);
	}

	int Client::Write(const std::vector<char>& buf) {
		return this->conn()->Write(buf);
	}

	int Client::Write(const std::string& buf) {
		return this->conn()->Write(buf);
	}

	int Client::ReadHeader(boost::asio::streambuf& buf) {
		return this->conn()->read_header(buf);
	}

} // namespace http

