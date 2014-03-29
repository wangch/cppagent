//
// request_handler.hpp
// ~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2013 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef HTTP_REQUEST_HANDLER_H_
#define HTTP_REQUEST_HANDLER_H_

#include "conn.h"
#include <string>
#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>

namespace http {

	class RequestHandler {
	public:
		RequestHandler(){}
		virtual ~RequestHandler(){}
		virtual void Handle(ConnBase* conn, const Request& req){}
	};

//struct reply;
//struct request;
//class connection;
//class ssl_conn;
//typedef boost::shared_ptr<connection> connection_ptr;
//typedef boost::shared_ptr<ssl_conn> ssl_conn_ptr;
//
///// The common handler for all incoming requests.
//class request_handler
//  : private boost::noncopyable
//{
//public:
//  /// Construct with a directory containing files to be served.
//  request_handler();
//  virtual ~request_handler();
//
//  /// Handle a request and produce a reply.
//  virtual bool handle_request(connection_ptr conn, const request& req, boost::asio::streambuf& res) = 0;
//  virtual void handle_request(ssl_conn_ptr conn, const request& req, boost::asio::streambuf& res) = 0;
//
//  /// Perform URL-decoding on a string. Returns false if the encoding was
//  /// invalid.
//  static bool url_decode(const std::string& in, std::string& out);
//
//private:
//};


} // namespace http

#endif // HTTP_REQUEST_HANDLER_H_
