/*
* Copyright 2019, Giorgio Zoppi
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*         http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
*        limitations under the License
*/
#include <string>
#include <vector>
#include <cstdlib>
#include <boost/date_time.hpp>
#include <amcl/mpin_BN254.h>
#include <bsd/stdlib.h>
#include <amcl/randapi.h>
#include <amcl/pbc_support.h>
#include <amcl/amcl.h>
#include <utils.h>
#include <secret_proxy.h>

namespace milagro
{
  namespace secure_store
  {

    using namespace BN254;
    using namespace boost::local_time;

      secret_proxy::secret_proxy ()
    {
      init_state ();
    }
    secret_proxy::secret_proxy (const std::string & path)
    {
      init_state ();

    }
    secret_proxy::~secret_proxy ()
    {
      KILL_CSPRNG (&_secure_random);
    }
    void secret_proxy::init_state ()
    {
      char raw[100];
      // FIXME this works only on linux and bsd
      arc4random_buf (raw, sizeof raw);
      amcl::octet row_octet =
      {
      0, sizeof (raw), raw};
      CREATE_CSPRNG (&_secure_random, &row_octet);
    }
    /*
     * Generate the D-TA master secret -
     * @param type  type of the store, optional parameter.
     */
    amcl::octet secret_proxy::generate_master_secret (store_type type)
    {
      char secret_chars[PGS_BN254];
      amcl::octet secret =
      {
      0, sizeof (secret_chars), secret_chars};
      _master_startTime = boost::posix_time::second_clock::local_time ();
      MPIN_RANDOM_GENERATE (&_secure_random, &secret);
      return secret;
    }
    /*
     *  Generate the client secret for the MPIN Protocol. 
     *  One between the user_id or the hash_pin_id shall be present.
     *  If juse the user_id is present create the hash from the user_id.
     *  @param user_id optional value for the user identifier
     *  @param hash_pin_id optional value for the mpin
     *  @returns An octect to be used as a secret key 
     */
    amcl::octet secret_proxy::generate_client_secret (const std::optional <
						      std::string > &user_id,
						      const std::optional <
						      std::string >
						      &hash_pin_id,
						      store_type type)
    {
      char client_id[256];
      char idhex[256];
      char token[2 * PFS_BN254 + 1];
      char hcid[PFS_BN254];
      amcl::octet HCID =
      {
      0, sizeof (hcid), hcid};
      amcl::octet CLIENT_ID =
      {
      0, sizeof (client_id), client_id};
      // compute when we shall expire.
      auto local = local_sec_clock::local_time (time_zone_ptr ());
      local += boost::gregorian::days (DAYS_CLIENT_SECRET_MAX);
      _client_expireTime = local.utc_time ();
      if (!user_id.has_value () && (!hash_pin_id.value ().size () == 64))
	{
	  throw std::invalid_argument ("Client identifier too long");
	}
      milagro::utils::make_hash_id (hash_pin_id, user_id, HCID);
      // we have here the hash id anyway.
      amcl::octet TOKEN =
      {
      0, sizeof (token), token};
      int currentSize = _master_secret.size ();
      amcl::octet S =
      {
      currentSize, currentSize,
	  const_cast < char *>(_master_secret.c_str ())};
      MPIN_GET_CLIENT_SECRET (&S, &HCID, &TOKEN);
      return TOKEN;
    }
    /*
     *  Get the time permits 
     * @param mash_
     */
    std::vector < std::string >
      secret_proxy::get_time_permits (const
				      std::optional < std::string >
				      &mhash_pin_id, int count)
    {
      char permit[2 * PFS_BN254 + 1];
      int day = amcl::today ();
      std::vector < std::string > tmp;
      amcl::octet HCID;
      amcl::octet PERMIT =
      {
      0, sizeof (permit), permit};
      int currentSize = _master_secret.size ();
      amcl::octet S =
      {
      currentSize,
	  currentSize, const_cast < char *>(_master_secret.c_str ())};
      milagro::utils::make_hash_id (mhash_pin_id, std::nullopt, HCID);
      for (int i = 0; i < count; ++count)
	{
	  MPIN_GET_CLIENT_PERMIT (HASH_TYPE_BN254, day, &S, &HCID, &PERMIT);
	  // This encoding makes Time permit look random 
	  if (MPIN_ENCODING (&_secure_random, &PERMIT) != 0)
	    {
	      throw std::runtime_error ("Encoding permit is not possible");
	    }
	  std::string str = milagro::utils::octet_to_string (PERMIT);
	  tmp.push_back (str);
	  std::memset (&PERMIT, 0, sizeof (amcl::octet));
	}
      return tmp;
    }
    /*
     *
     */
    boost::posix_time::ptime secret_proxy::client_key_expire ()const
    {
      return _client_expireTime;
    }
    /*
     *
     */
    boost::posix_time::ptime secret_proxy::server_key_start () const
    {
      return _master_startTime;
    }
    /*
     *  
     */
    std::optional < amcl::octet > secret_proxy::search_key (int appId)
    {
      auto value = _key_store.find (appId);
      if (value != _key_store.end ())
	{
	  return std::make_optional < amcl::octet > (value->second);
	}
      return std::nullopt;

    }

  }
}
