//
// cert_util.h  
//

#ifndef _GOAGENT_CERTUTIL_H_
#define _GOAGENT_CERTUTIL_H_

#include <string>

#include <boost/utility.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>

class CertUtil : boost::noncopyable {
	CertUtil();
	static boost::weak_ptr<CertUtil> singleton_;

public:
	~CertUtil();
	static boost::shared_ptr<CertUtil> Get() {
		boost::shared_ptr<CertUtil> instance = singleton_.lock();
		if (!instance) {
			instance.reset(new CertUtil());
			singleton_ = instance;
		}

		return instance;
	}

	bool CheckCA(std::string app_name);
	std::string GetCert(const std::string& host);
private:
	void create_ca();
	void dump_ca();
	int get_cert(const std::string& cname, std::string& fname);
	bool import_ca(const std::string& path);
private:
};


#endif // _GOAGENT_CERTUTIL_H_