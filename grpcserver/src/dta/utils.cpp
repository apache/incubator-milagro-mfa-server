#include <optional>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sstream>
#include <iomanip>      // std::setfill, std::setw
#include <proto-generated/mpin.pb.h>
#include <amcl/amcl.h>
#include <amcl/mpin_BN254.h>
#include <bsd/stdlib.h>
#include <boost/algorithm/hex.hpp>
#include <utils.h>


namespace milagro
{
  namespace utils
  {
    std::string octet_to_string (const amcl::octet & y)
    {
      std::string s;
      s.reserve (y.max);
      int i
      {
      0};
      int j
      {
      y.len};
      for (int i = 0; i < y.max; ++i)
	{
	  s[i] = y.val[i];
	}
      return s;
    }
    std::string tohex (const std::string & s, bool upper)
    {
      std::ostringstream ret;
      unsigned int c;
      for (std::string::size_type i = 0; i < s.length (); ++i)
	{
	  c = (unsigned int) (unsigned char) s[i];
	  ret << std::hex << std::setfill ('0') <<
	    std::setw (2)  << c;
	}
      return ret.str ();
    }

    std::string make_mpin_id (const std::string & clientid)
    {
      MPinIdentifier mpin_id;
      char raw[16];
      arc4random_buf (raw, sizeof raw);
      std::string salt (raw);
      google::protobuf::Timestamp *status = new google::protobuf::Timestamp();
      status->set_seconds(time(NULL));
      
      mpin_id.set_allocated_issued (status);
      mpin_id.set_userid (clientid);
      mpin_id.set_salt (salt);
      // now i shall compute the salt
      std::shared_ptr<std::string> output = std::make_shared<std::string>();
      output->reserve (512);
      mpin_id.SerializeToString (output.get());
      auto outhex =  tohex (*output, false);
      return outhex;
    }
    

  std::string sha256_hash (const std::string & current)
  {
    // todo: return an hash
    return current;
  }
  MPinIdentifier decode_mpin (const std::string & mpinSerialized)
  {
    MPinIdentifier identifer;
    // todo this shall be moved values.
    identifer.set_activatekey ("89289");
    identifer.set_userid ("jo");
    // todo more fields to be from the origianl mpinSerialized
    // that it shall be decoded for real.
    return identifer;;
  }


  void make_hash_id (const std::optional < std::string > &hash_pin_id,
		     const std::optional < std::string > &user_id,
		     amcl::octet & HCID)
  {
    char client_id[256];
    amcl::octet CLIENT_ID =
    {
    0, sizeof (client_id), client_id};
    char hcid[PFS_BN254];
    amcl::octet tmpHCID =
    {
    0, sizeof (hcid), hcid};

    // in case we have the user id we will use it
    if (user_id.has_value () > 0)
      {
	std::memcpy (client_id, user_id.value ().c_str (),
		     sizeof (client_id));
	OCT_jstring (&CLIENT_ID,
		     const_cast < char *>(user_id.value ().c_str ()));
	HASH_ID (HASH_TYPE_BN254, &CLIENT_ID, &tmpHCID);
      }
    else
      {
	std::memcpy (hcid, hash_pin_id.value ().c_str (), sizeof (hcid));
      }

    HCID.max = tmpHCID.max;
    HCID.val = tmpHCID.val;
    HCID.len = tmpHCID.len;

  }
  }
}



  // octet
