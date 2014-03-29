//
// cert_util.cc
//

#include "cert_util.h"
#include "base64.h"
#ifdef WIN32
#include <windows.h> // ½â¾öX509_NAME ³åÍ»
#endif // WIN32

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/md5.h>

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <iostream>
#include <sstream>

boost::weak_ptr<CertUtil> CertUtil::singleton_;

namespace fs = boost::filesystem;

const std::string ca_vendor = "GoAgent";
const std::string ca_keyfile = "CA.crt";
const std::string ca_certdir = "certs";


CertUtil::CertUtil() {

}

CertUtil::~CertUtil() {

}

bool CertUtil::CheckCA(std::string app_name) {
	fs::path dir = fs::complete(app_name).branch_path();
	fs::path ca_path = dir /= ca_keyfile;
	fs::path ca_dir = dir /= ca_certdir;

	if (!fs::exists(ca_path)) {
		if (fs::exists(ca_dir)) {
			if (fs::is_directory(ca_dir)) {
				for (auto it = fs::directory_iterator(ca_dir); it != fs::directory_iterator(); ++it) {
					if (boost::ends_with(it->path().string(), ".key")) {
						fs::remove(it->path());
					}
				}
			} else {
				fs::remove(ca_dir);
				fs::create_directory(ca_dir);
			}
		}
		dump_ca();
	}

	if (fs::exists(ca_dir)) {
		if (fs::is_directory(ca_dir)) {
			for (auto it = fs::directory_iterator(ca_dir); it != fs::directory_iterator(); ++it) {
				if (boost::ends_with(it->path().string(), ".key")) {
					fs::remove(it->path());
				}
				if (boost::ends_with(it->path().string(), ".crt")) {
					fs::remove(it->path());
				}
			}
		}
	}

	if (!fs::exists(ca_dir)) {
		fs::create_directory(ca_dir);
	}

	if (!this->import_ca(ca_path.string())) {

		return false;
	}
	return true;
}

static void callback(int p, int n, void *arg)
{
	char c='B';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
}

int add_ext(X509 *cert, int nid, char *value);

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name = NULL;

	if ((pkeyp == NULL) || (*pkeyp == NULL))
	{
		if ((pk=EVP_PKEY_new()) == NULL)
		{
			abort(); 
			return(0);
		}
	}
	else
		pk= *pkeyp;

	if ((x509p == NULL) || (*x509p == NULL))
	{
		if ((x=X509_new()) == NULL)
			goto err;
	}
	else
		x= *x509p;

	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
	{
		abort();
		goto err;
	}
	rsa=NULL;

	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x,pk);

	name=X509_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	* correct string type and performing checks on its length.
	* Normally we'd check the return value for errors...
	*/
	X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC, (unsigned char*)"CN", -1, -1, 0);
	const char *cn = (ca_vendor + " CA").c_str();
	X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"ST", MBSTRING_ASC, (unsigned char*)"Internet", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, (unsigned char*)"Cernet", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, (unsigned char*)ca_vendor.c_str(), -1, -1, 0);
	const char *ou = (ca_vendor + " ROOT").c_str();
	X509_NAME_add_entry_by_txt(name,"OU", MBSTRING_ASC, (unsigned char*)ou, -1, -1, 0);

	/* Its self signed so set the issuer name to be the same as the
	* subject.
	*/
	X509_set_issuer_name(x,name);

	/* Add various extensions: standard extensions */
	add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(x, NID_netscape_cert_type, "sslCA");
	add_ext(x, NID_key_usage, "keyCertSign, cRLSign");
	add_ext(x, NID_ext_key_usage, "serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC");
	add_ext(x, NID_subject_key_identifier, "hash");

	if (!X509_sign(x,pk,EVP_sha1()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
}

/* Add extension using V3 code: we can set the config file as NULL
* because we wont reference any other sections.
*/

int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	* no request and no CRL
	*/
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

void CertUtil::dump_ca() {
	X509 *x509=NULL;
	EVP_PKEY *pkey=NULL;

	mkcert(&x509, &pkey, 512, 0, 365);

	FILE *f = fopen(ca_keyfile.c_str(), "wb");
	if (f != nullptr) {
		PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
		PEM_write_X509(f, x509);
		fclose(f);
	}

	X509_free(x509);
	EVP_PKEY_free(pkey);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
}

bool CertUtil::import_ca(const std::string& path) {
#ifdef WIN32
	std::string cert_data;
	std::ifstream fi(path);
	fi >> cert_data;
	if (boost::starts_with(cert_data, "-----")) {
		std::string begin("-----BEGIN CERTIFICATE-----");
		std::string end("-----END CERTIFICATE-----");
		size_t pos = cert_data.find(begin);
		size_t pos2 = cert_data.find(end);
		cert_data = cert_data.substr(pos+begin.length(), pos2 - end.length());
		boost::trim(cert_data);
		std::vector<std::string> v;
		boost::split(v, cert_data, boost::is_any_of("/n"));
		cert_data = boost::join(v, "");
		std::stringstream os;
		std::copy(base64_encode(cert_data.c_str()), 
			base64_encode(cert_data.c_str() + cert_data.length()), 
			bai::ostream_iterator<char>(os));
		cert_data = os.str();
	}

	typedef HCERTSTORE (*CertOpenStore)(
		_In_  LPCSTR lpszStoreProvider,
		_In_  DWORD dwMsgAndCertEncodingType,
		_In_  HCRYPTPROV_LEGACY hCryptProv,
		_In_  DWORD dwFlags,
		_In_  const void *pvPara
		);

	HMODULE crypt32_handle = ::LoadLibrary("crypt32.dll");
	if (crypt32_handle == NULL) {
		return false;
	}

	CertOpenStore cert_open_store = (CertOpenStore)::GetProcAddress(crypt32_handle, "CertOpenStore");
	if (cert_open_store == NULL) {
		::FreeLibrary(crypt32_handle);
		return false;
	}
	HCERTSTORE store_handle = cert_open_store(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_NO_ISSUER_FLAG, "ROOT");
	if (store_handle == NULL) {
		return false;
	}

	typedef BOOL (*CertAddEncodedCertificateToStore)(
		_In_       HCERTSTORE hCertStore,
		_In_       DWORD dwCertEncodingType,
		_In_       const BYTE *pbCertEncoded,
		_In_       DWORD cbCertEncoded,
		_In_       DWORD dwAddDisposition,
		_Out_opt_  PCCERT_CONTEXT *ppCertContext
		);
	CertAddEncodedCertificateToStore caect = (CertAddEncodedCertificateToStore)::GetProcAddress(crypt32_handle, "CertAddEncodedCertificateToStore");
	if (caect == NULL) {
		return false;
	}
	BOOL b = caect(store_handle, 0x1, (const BYTE*)cert_data.c_str(), cert_data.length(), 4, NULL);
	typedef BOOL (*CertCloseStore)(
		_In_  HCERTSTORE hCertStore,
		_In_  DWORD dwFlags
		);

	CertCloseStore close_store = (CertCloseStore)::GetProcAddress(crypt32_handle, "CertCloseStore");
	if (close_store == NULL) {
		return false;
	}
	close_store(store_handle, 0);
	::FreeLibrary(crypt32_handle);
	return b == TRUE;
#endif
#ifdef LINUX
#endif
#ifdef DARWIN
#endif
	return false;
}

std::string CertUtil::GetCert(const std::string& host) {
	std::string s(host);
	std::vector<std::string> v;
	boost::split(v, host, boost::is_any_of("."));
	if (v.size() > 2 && v[v.size()-2].length() > 4) {
		std::size_t pos = host.find(".");
		s = host.substr(pos);
	}
	fs::path ca_file(ca_certdir);
	ca_file /= s + ".crt";
	if (fs::exists(ca_file)) {
		return ca_file.string();
	} else {
		std::string fname;
		int r = get_cert(s, fname);
		return fname;
	}

	return "";
}

int mkreq(X509_REQ **req, EVP_PKEY **pkeyp, const std::string& cname)
{
	X509_REQ *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;
	STACK_OF(X509_EXTENSION) *exts = NULL;

	if ((pk=EVP_PKEY_new()) == NULL)
		goto err;

	if ((x=X509_REQ_new()) == NULL)
		goto err;

	rsa=RSA_generate_key(2048,RSA_F4,callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		goto err;

	rsa=NULL;

	X509_REQ_set_pubkey(x,pk);

	name=X509_REQ_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	* correct string type and performing checks on its length.
	* Normally we'd check the return value for errors...
	*/
	X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC, (unsigned char*)"CN", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"ST", MBSTRING_ASC, (unsigned char*)"Internet", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, (unsigned char*)"Cernet", -1, -1, 0);
	const char *ou = (ca_vendor + " Branch").c_str();
	X509_NAME_add_entry_by_txt(name,"OU", MBSTRING_ASC, (unsigned char*)ou, -1, -1, 0);

	if (cname.length() > 0) {
		if (cname[0] == '.') {
			std::string cn = "*" + cname;
			X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
		} else {
			std::string cn = cname;
			X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (unsigned char*)cname.c_str(), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, (unsigned char*)cname.c_str(), -1, -1, 0);
		}
	}
	

	if (!X509_REQ_sign(x,pk,EVP_sha1()))
		goto err;

	*req=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
}

int CertUtil::get_cert(const std::string& cname, std::string& fname) {
	FILE *f = fopen(ca_keyfile.c_str(), "rb");
	if (!f) {
		return -1;
	}

	EVP_PKEY *rpk;
	PEM_read_PrivateKey(f, &rpk, NULL, 0);
	fclose(f);

	std::string content;
	std::ifstream fi(ca_keyfile);
	fi >> content;

	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == nullptr) {
		return -1;
	}
	BIO_puts(bio, content.c_str());
	X509* ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	X509_REQ* req;
	EVP_PKEY *pk;
	mkreq(&req, &pk, cname);

	X509 *x = X509_new();
	X509_set_version(x,2);
	unsigned char md[MD5_DIGEST_LENGTH];
	MD5((const unsigned char*)cname.c_str(), cname.length(), md);
	std::string num;
	for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		num += std::to_string(md[i]);
	}
	char* end; 
	unsigned long n = std::strtoul(num.c_str(), &end, 16);
	ASN1_INTEGER_set(X509_get_serialNumber(x),n);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*3652);
	X509_set_pubkey(x,pk);
	X509_set_subject_name(x, X509_REQ_get_subject_name(req));
	X509_set_issuer_name(x, X509_get_subject_name(ca));
	X509_sign(x,rpk,EVP_sha1());

	fs::path ca_file(ca_certdir);
	ca_file /= cname + ".crt";
	fname = ca_file.string();
	f = fopen(fname.c_str(), "wb");
	if (f != nullptr) {
		PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL);
		PEM_write_X509(f, x);
		fclose(f);
	}
	
	EVP_PKEY_free(pk);
	EVP_PKEY_free(rpk);
	X509_REQ_free(req);
	X509_free(x);
	X509_free(ca);
	return 0;
}
