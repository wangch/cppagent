//
// base64.h  
//

#ifndef _GOAGENT_BASE64_H_
#define _GOAGENT_BASE64_H_

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>

namespace bai = boost::archive::iterators;

typedef bai::base64_from_binary<
	bai::transform_width<const char *, 8, 6 >> base64_encode;

typedef bai::transform_width<
	bai::binary_from_base64<const char *>, 6, 8> base64_decode;

#endif // _GOAGENT_BASE64_H_
