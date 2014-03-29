//
// dns.util.h 
//

#ifndef _GOAGENT_DNSUTIL_H_
#define _GOAGENT_DNSUTIL_H_

#include <boost/asio.hpp>
#include <string>
#include <vector>


class DnsUtil {
	boost::asio::io_service& ios_;
public:
	DnsUtil(boost::asio::io_service& ios);
	~DnsUtil();
	std::vector<std::string> remote_resolve(
		const std::string& host, 
		const std::string& port, 
		const std::string& qname);
private:
	int max_retry_;
	int max_wait_;
};

#endif // _GOAGENT_DNSUTIL_H_