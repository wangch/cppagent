//
// dns_util.cc
//


#include "dns_util.h"


namespace dns {
    //http://gfwrev.blogspot.com/2009/11/gfwdns.html
    //http://zh.wikipedia.org/wiki/ÓòÃû·þÎñÆ÷»º´æÎÛÈ¾
    //http://support.microsoft.com/kb/241352

	std::string black_list[] = {
		"1.1.1.1",
		"255.255.255.255",
		// for google+
		"74.125.127.102",
		"74.125.155.102",
		"74.125.39.102",
		"74.125.39.113",
		"209.85.229.138",
		// other ip list
		"4.36.66.178",
		"8.7.198.45",
		"37.61.54.158",
		"46.82.174.68",
		"59.24.3.173",
		"64.33.88.161",
		"64.33.99.47",
		"64.66.163.251",
		"65.104.202.252",
		"65.160.219.113",
		"66.45.252.237",
		"72.14.205.104",
		"72.14.205.99",
		"78.16.49.15",
		"93.46.8.89",
		"128.121.126.139",
		"159.106.121.75",
		"169.132.13.103",
		"192.67.198.6",
		"202.106.1.2",
		"202.181.7.85",
		"203.161.230.171",
		"203.98.7.65",
		"207.12.88.98",
		"208.56.31.43",
		"209.145.54.50",
		"209.220.30.174",
		"209.36.73.33",
		"211.94.66.147",
		"213.169.251.35",
		"216.221.188.182",
		"216.234.179.13",
		"243.185.187.39"
	};
} // namespace dns


DnsUtil::DnsUtil(boost::asio::io_service& ios) 
	: ios_(ios), max_retry_(3), max_wait_(3) {
}

DnsUtil::~DnsUtil() {
}

std::vector<std::string> DnsUtil::remote_resolve(const std::string& host, 
												 const std::string& port, 
												 const std::string& qname) 
{
	std::vector<std::string> v;
	for (int i = 0; i < this->max_retry_; ++i) {
		if (i < this->max_retry_ - 1) {
			boost::asio::ip::udp::socket udp_socket_(this->ios_);
			boost::asio::ip::tcp::resolver resolver(this->ios_);
		} else {
			boost::asio::ip::tcp::socket tcp_socket_(this->ios_);
		}
	}
	return v;
}


