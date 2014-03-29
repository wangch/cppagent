//
// common.h
//

#ifndef _GOAGENT_COMMON_H_
#define _GOAGENT_COMMON_H_

#include <string>
#include <vector>
#include <map>
#include <deque>

#include <boost/utility.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>

class Common : boost::noncopyable {
	Common();
	static boost::weak_ptr<Common> singleton_;

public:
	~Common();
	static boost::shared_ptr<Common> Get() {
		boost::shared_ptr<Common> instance = singleton_.lock();
		if (!instance) {
			instance.reset(new Common());
			instance->Init();
			singleton_ = instance;
		}

		return instance;
	}

	int Init();
	std::string Info();

public:
	std::string LISTEN_IP;
	std::string LISTEN_PORT;
	int	LISTEN_VISIBLE;
	int	LISTEN_DEBUGINFO;

	std::deque<std::string> GAE_APPIDS;
	std::string	GAE_PASSWORD;
	std::string	GAE_PATH;
	std::string	GAE_PROFILE;
	int	GAE_CRLF;
	int	GAE_VALIDATE;
	int	GAE_OBFUSCATE;

	int	PAC_ENABLE;
	std::string	PAC_IP;
	int	PAC_PORT;
	std::string	PAC_FILE;
	std::string	PAC_GFWLIST;
	int	PAAS_ENABLE;
	std::string	PAAS_LISTEN;
	std::string	PAAS_PASSWORD;
	int	PAAS_VALIDATE;
	std::string	PAAS_FETCHSERVER;

	int	PROXY_ENABLE;
	int	PROXY_AUTODETECT;
	std::string	PROXY_HOST;
	int	PROXY_PORT;
	std::string	PROXY_USERNAME;
	std::string	PROXY_PASSWROD;
	std::string proxy;

	std::string GOOGLE_MODE;
	int GOOGLE_WINDOW;
	std::vector<std::string> GOOGLE_HOSTS;
	std::vector<std::string> GOOGLE_SITES;
	std::vector<std::string> GOOGLE_FORCEHTTPS;
	std::vector<std::string> GOOGLE_WITHGAE;

	std::vector<std::string> AUTORANGE_HOSTS;
	std::vector<std::string> AUTORANGE_HOSTS_MATCH;
	std::vector<std::string> AUTORANGE_ENDSWITH;
	std::vector<std::string> AUTORANGE_NOENDSWITH;
	int AUTORANGE_MAXSIZE;
	int AUTORANGE_WAITSIZE;
	int AUTORANGE_BUFSIZE;
	int AUTORANGE_THREADS;

	int FETCHMAX_LOCAL;
	std::string FETCHMAX_SERVER;

	int DNS_ENABLE;
	std::string	DNS_LISTEN;
	std::string	DNS_REMOTE;
	int	DNS_TIMEOUT;
	int	DNS_CACHESIZE;

	int LIGHT_ENABLE;
	std::string LIGHT_PASSWORD;
	std::string LIGHT_LISTEN;
	std::string LIGHT_SERVER;

	int USERAGENT_ENABLE;
	std::string USERAGENT_STRING;

	int LOVE_ENABLE;
	std::string LOVE_TIP;

	std::map<std::string, std::string> HOSTS;
	std::map<std::string, std::string> HOSTS_MATCH;
	std::map<std::string, std::string> HOSTS_CONNECT_MATCH;

	std::string GAE_FETCHSERVER;
};


#endif // _GOAGENT_COMMON_H_