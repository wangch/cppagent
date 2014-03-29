//
// common.cc
//

#include "common.h"
#include <glog/logging.h>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <regex>

boost::weak_ptr<Common> Common::singleton_;

namespace ini_parser = boost::property_tree::ini_parser;

Common::Common() {
}

Common::~Common() {
}

 
/*
 * Return a new string with all occurrences of 'from' replaced with 'to'
 */
std::string replace_all(const std::string &str, const char *from, const char *to)
{
    std::string result(str);
    std::string::size_type
        index = 0,
        from_len = strlen(from),
        to_len = strlen(to);
    while ((index = result.find(from, index)) != std::string::npos) {
        result.replace(index, from_len, to);
        index += to_len;
    }
    return result;
}

static std::string translate(const char *pattern) {
    int i = 0, n = strlen(pattern);
    std::string result;
 
    while (i < n) {
        char c = pattern[i];
        ++i;
 
        if (c == '*') {
            result += ".*";
        } else if (c == '?') {
            result += '.';
        } else if (c == '[') {
            int j = i;
            /*
             * The following two statements check if the sequence we stumbled
             * upon is '[]' or '[!]' because those are not valid character
             * classes.
             */
            if (j < n && pattern[j] == '!')
                ++j;
            if (j < n && pattern[j] == ']')
                ++j;
            /*
             * Look for the closing ']' right off the bat. If one is not found,
             * escape the opening '[' and continue.  If it is found, process
             * the contents of '[...]'.
             */
            while (j < n && pattern[j] != ']')
                ++j;
            if (j >= n) {
                result += "\\[";
            } else {
                std::string stuff = replace_all(std::string(&pattern[i], j - i), "\\", "\\\\");
                char first_char = pattern[i];
                i = j + 1;
                result += "[";
                if (first_char == '!') {
                    result += "^" + stuff.substr(1);
                } else if (first_char == '^') {
                    result += "\\" + stuff;
                } else {
                    result += stuff;
                }
                result += "]";
            }
        } else {
            if (isalnum(c)) {
                result += c;
            } else {
                result += "\\";
                result += c;
            }
        }
    }
    /*
     * Make the expression multi-line and make the dot match any character at all.
     */
    return result + "\\Z(?ms)";
}

int Common::Init() {
	boost::property_tree::ptree pt;
	ini_parser::read_ini("./proxy.ini", pt);

	this->LISTEN_IP = pt.get<std::string>("listen.ip");
	this->LISTEN_PORT = pt.get<std::string>("listen.port");
	this->LISTEN_VISIBLE = pt.get<int>("listen.visible");
	this->LISTEN_DEBUGINFO = pt.get<int>("listen.debuginfo");

	std::string str = pt.get<std::string>("gae.appid");
	std::string s(".appspot.com");
	for (std::size_t pos = str.find(s); pos != std::string::npos; pos = str.find(s)) {
		str = str.replace(pos, s.length(), "");
	}

	std::regex r("[\\w\\-\\.]+");
	std::smatch m;
	if (std::regex_match(str, m, r)) {
		for (size_t i = 0; i < m.size(); i++) {
			this->GAE_APPIDS.push_back(m[i].str());
		}	
	}
	this->GAE_PASSWORD = pt.get<std::string>("gae.password");
	this->GAE_PATH = pt.get<std::string>("gae.path");
	this->GAE_PROFILE = pt.get<std::string>("gae.profile");
	this->GAE_CRLF = pt.get<int>("gae.crlf");
	this->GAE_VALIDATE = pt.get<int>("gae.validate");
	this->GAE_OBFUSCATE = pt.get<int>("gae.obfuscate");

	this->PAC_ENABLE = pt.get<int>("pac.enable");
	this->PAC_IP = pt.get<std::string>("pac.ip");
	this->PAC_PORT = pt.get<int>("pac.port");
	this->PAC_FILE = pt.get<std::string>("pac.file");
	this->PAC_GFWLIST = pt.get<std::string>("pac.gfwlist");

	this->PAAS_ENABLE = pt.get<int>("paas.enable");
	this->PAAS_PASSWORD = pt.get<std::string>("paas.password");
	this->PAAS_VALIDATE = pt.get<int>("paas.validate");
	this->PAAS_FETCHSERVER = pt.get<std::string>("paas.fetchserver");

	this->PROXY_ENABLE = pt.get<int>("proxy.enable");
	this->PROXY_AUTODETECT = pt.get<int>("proxy.autodetect");
	this->PROXY_HOST = pt.get<std::string>("proxy.host");
	this->PROXY_PORT = pt.get<int>("proxy.port");
	this->PROXY_USERNAME = pt.get<std::string>("proxy.username");
	this->PROXY_PASSWROD = pt.get<std::string>("proxy.password");

	if (this->PROXY_ENABLE == 1) {
		this->GOOGLE_MODE = "https";
		auto fmt = boost::format("https://%s:%s@%s:%d") % this->PROXY_USERNAME % this->PROXY_PASSWROD % this->PROXY_HOST % this->PROXY_PORT;
		this->proxy = fmt.str();
	} else if (this->PROXY_AUTODETECT) {
		// TODO: ProxyUtil.get_system_proxy()
	}

	this->GOOGLE_MODE = pt.get<std::string>(this->GAE_PROFILE + ".mode");
	this->GOOGLE_MODE = pt.get<int>(this->GAE_PROFILE + ".window");
	str = pt.get<std::string>(this->GAE_PROFILE + ".hosts");
	s = "|";
	for (std::size_t pos = str.find("|"); pos != std::string::npos; pos = str.find("|")) {
		s = str.substr(0, pos);
		str = str.substr(pos+1);
		this->GOOGLE_HOSTS.push_back(s);
	}
	this->GOOGLE_HOSTS.push_back(str);
	str = pt.get<std::string>(this->GAE_PROFILE + ".sites");
	for (std::size_t pos = str.find("|"); pos != std::string::npos; pos = str.find("|")) {
		s = str.substr(0, pos);
		str = str.substr(pos+1);
		this->GOOGLE_SITES.push_back(s);
	}
	this->GOOGLE_SITES.push_back(str);
	str = pt.get<std::string>(this->GAE_PROFILE + ".forcehttps");
	for (std::size_t pos = str.find("|"); pos != std::string::npos; pos = str.find("|")) {
		s = str.substr(0, pos);
		str = str.substr(pos+1);
		this->GOOGLE_FORCEHTTPS.push_back("http://" + s);
	}
	this->GOOGLE_FORCEHTTPS.push_back("http://" + str);
	str = pt.get<std::string>(this->GAE_PROFILE + ".withgae");
	for (std::size_t pos = str.find("|"); pos != std::string::npos; pos = str.find("|")) {
		s = str.substr(0, pos);
		str = str.substr(pos+1);
		this->GOOGLE_WITHGAE.push_back(s);
	}
	this->GOOGLE_WITHGAE.push_back(str);

	str = pt.get<std::string>("autorange.hosts");
	for (std::size_t pos = str.find("|"); pos != std::string::npos; pos = str.find("|")) {
		s = str.substr(0, pos);
		str = str.substr(pos+1);
		this->AUTORANGE_HOSTS.push_back(s);
	}
	for (auto it = this->AUTORANGE_HOSTS.begin(); it != this->AUTORANGE_HOSTS.end(); ++it) {
		std::string m = translate(it->c_str());
		this->AUTORANGE_HOSTS_MATCH.push_back(m);
	}
	str = pt.get<std::string>("autorange.endswith");
	for (std::size_t pos = str.find("|"); pos != std::string::npos; pos = str.find("|")) {
		s = str.substr(0, pos);
		str = str.substr(pos+1);
		this->AUTORANGE_ENDSWITH.push_back(s);
	}
	this->AUTORANGE_ENDSWITH.push_back(str);
	str = pt.get<std::string>("autorange.noendswith");
	for (std::size_t pos = str.find("|"); pos != std::string::npos; pos = str.find("|")) {
		s = str.substr(0, pos);
		str = str.substr(pos+1);
		this->AUTORANGE_NOENDSWITH.push_back(s);
	}
	this->AUTORANGE_NOENDSWITH.push_back(str);
	this->AUTORANGE_MAXSIZE = pt.get<int>("autorange.maxsize");
	this->AUTORANGE_WAITSIZE = pt.get<int>("autorange.waitsize");
	this->AUTORANGE_BUFSIZE = pt.get<int>("autorange.bufsize");
	this->AUTORANGE_THREADS = pt.get<int>("autorange.threads");

	this->FETCHMAX_LOCAL = pt.get<int>("fetchmax.local");
	if (this->FETCHMAX_LOCAL == 0) {
		this->FETCHMAX_LOCAL = 3;
	}
	this->FETCHMAX_SERVER = pt.get<std::string>("fetchmax.server");

	this->DNS_ENABLE = pt.get<int>("dns.enable");
	this->DNS_LISTEN = pt.get<std::string>("dns.listen");
	this->DNS_REMOTE = pt.get<std::string>("dns.remote");
	this->DNS_TIMEOUT = pt.get<int>("dns.timeout");
	this->DNS_CACHESIZE = pt.get<int>("dns.cachesize");

	this->LIGHT_ENABLE = pt.get<int>("light.enable");
	this->LIGHT_PASSWORD = pt.get<std::string>("light.password");
	this->LIGHT_LISTEN = pt.get<int>("light.timeout");
	this->LIGHT_SERVER = pt.get<int>("light.cachesize");

	this->USERAGENT_ENABLE = pt.get<int>("useragent.enable");
	this->USERAGENT_STRING = pt.get<std::string>("useragent.string");

	this->LOVE_ENABLE = pt.get<int>("love.enable");
	this->LOVE_TIP = pt.get<std::string>("love.tip");

	auto& l = pt.get_child("hosts");
	for (auto it = l.begin(); it != l.end(); it++) {
		this->HOSTS.insert(std::make_pair(it->first, it->second.data()));
	}
	for (auto it = this->HOSTS.begin(); it != this->HOSTS.end(); ++it) {
		std::regex re("\\d+$");
		if (!std::regex_search(it->first, re)) {
			this->HOSTS_MATCH.insert(*it);
		}
	}
	for (auto it = this->HOSTS.begin(); it != this->HOSTS.end(); ++it) {
		std::regex re("\\d+$");
		if (std::regex_search(it->first, re)) {
			this->HOSTS_CONNECT_MATCH.insert(*it);
		}
	}

	auto fmt = boost::format("%s://%s.appspot.com%s?") % this->GOOGLE_MODE % this->GAE_APPIDS[0] % this->GAE_PATH;
	this->GAE_FETCHSERVER = fmt.str();

	return 0;
}

std::string Common::Info() {
	std::string appids;
	for (auto &it = this->GAE_APPIDS.begin(); it != this->GAE_APPIDS.end(); ++it) {
		appids += *it + "|";
	}
	std::stringstream info("------------------------------------------------------\n");
	info << boost::format("GoAgent Version    : %f\n") % 1.0;
	info << boost::format("Listen Address     : %s:%d\n") % this->LISTEN_IP % this->LISTEN_PORT;
	info << boost::format("Local Proxy        : %s:%s\n") % this->PROXY_HOST % this->PROXY_PORT;
	info << boost::format("Debug INFO         : %s\n") % this->LISTEN_DEBUGINFO;
	info << boost::format("GAE Mode           : %s\n") % this->GOOGLE_MODE;
	info << boost::format("GAE Profile        : %s\n") % this->GAE_PROFILE;
	info << boost::format("GAE APPID          : %s\n") % appids;
	info << boost::format("GAE Validate       : %s\n") % this->GAE_VALIDATE;
	info << boost::format("GAE Obfuscate      : %s\n") % this->GAE_OBFUSCATE;
	if (this->PAC_ENABLE == 1) {
		info << boost::format("Pac Server         : http://%s:%d/%s\n") % this->PAC_IP % this->PAC_PORT % this->PAC_FILE;
		info << boost::format("Pac File           : file://%s\n") % "proxy.pac";
	}
	if (this->PAAS_ENABLE == 1) {
		info << boost::format("PAAS Listen        : %s\n") % this->PAAS_LISTEN;
		info << boost::format("PAAS FetchServer   : %s\n") % this->PAAS_FETCHSERVER;
	}												 
	if (this->DNS_ENABLE == 1) {						 
		info << boost::format("DNS Listen         : %s\n") % this->DNS_LISTEN;
		info << boost::format("DNS Remote         : %s\n") % this->DNS_REMOTE;
	}													 
	if (this->LIGHT_ENABLE == 1) {						 
		info << boost::format("LIGHT Listen       : %s\n") % this->LIGHT_LISTEN;
		info << boost::format("LIGHT Server       : %s\n") % this->LIGHT_SERVER;
	}
	info << "------------------------------------------------------\n";
	return info.str();
}
