#ifndef _MILAGRO_OCT_UTILS_H
#define _MILAGRO_OCT_UTILS_H

#include <amcl/amcl.h>
#include <string>
#include <optional>
#include <proto-generated/mpin.pb.h>

namespace milagro
{
  namespace utils
  {
    extern std::string octet_to_string (const amcl::octet & y);

    extern void make_hash_id (const std::optional < std::string >
			      &hash_pin_id,
			      const std::optional < std::string > &user_id,
			      amcl::octet & HCID);
    extern std::string make_mpin_id (const std::string & userId);
      std::string sha256_hash (const std::string & current);

    extern MPinIdentifier decode_mpin (const std::string & mpinSerialized);
    extern std::string tohex (const std::string & s, bool upper = false);

  }				// name
}
#endif
