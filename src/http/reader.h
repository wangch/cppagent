//
// reader.h
// 


#ifndef HTTP_READER_H_
#define HTTP_READER_H_

#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>

class Reader : public boost::noncopyable {
public:
	Reader() {

	}

	virtual ~Reader() {

	}

	virtual int Read(int len, boost::asio::streambuf& buf) {
		return -1;
	}

	virtual int Serve() {

	}
};

#endif // HTTP_READER_H_
