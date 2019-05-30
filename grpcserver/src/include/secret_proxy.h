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
#ifndef SECRET_PROXY_H
#define SECRET_PROXY_H
#include <amcl/amcl.h>
#include <string>
#include <optional>
#include <vector>
#include <map>
#include <boost/date_time.hpp>
#include <amcl/randapi.h>
#include <amcl/mpin_BN254.h>


namespace milagro
{
  using namespace BN254;

  namespace secure_store
  {
    // days of live of the client secret
    // fixme this shall be configurable
    const int DAYS_CLIENT_SECRET_MAX = 30;
    const int RNG_ERROR = 30;

    typedef enum store_type
    {
      hsm_store = 0x01,
      json_store = 0x02
    };
    class secret_proxy
    {
    public:
      /*
       * Construct a proxy for the secret retrieval. The idea is that the secret 
       * location is indipendent from the access. 
       */
      secret_proxy ();
      ~secret_proxy ();

      /*
       * Construct a proxy for the secret retrieval
       * @param configuration file parameters.
       */
      secret_proxy (const std::string & config);
      /*
       *  We dont want copy in case of a secret_proxy.
       */
        secret_proxy (const secret_proxy & copy) = delete;
      const secret_proxy & operator= (const secret_proxy & copy) = delete;
      /*
       * Generate the D-TA master secret. Defaule store is json on disk, 
       * this might change.
       * @param type  type of the store, std::optional parameter.
       */
        amcl::octet generate_master_secret (store_type type =
					    store_type::json_store);
      /*
       *  Generate the client secret for the MPIN Protocol. 
       *  One between the user_id or the hash_pin_id shall be present.
       *  If juse the user_id is present create the hash from the user_id.
       *  @param user_id std::optional value for the user identifier
       *  @param hash_pin_id std::optional value for the mpin
       *  @returns An octect to be used as a secret key 
       */
        amcl::octet generate_client_secret (const std::optional <
					    std::string > &user_id,
					    const std::optional <
					    std::string > &hash_pin_id,
					    store_type type =
					    store_type::json_store);

        std::vector < std::string > get_time_permits (const
						      std::optional <
						      std::string >
						      &mhash_pin_id,
						      int count = 1);
        boost::posix_time::ptime client_key_expire () const;
        boost::posix_time::ptime server_key_start () const;
        std::optional < amcl::octet > search_key (int appId);

    private:
      void init_state ();
        std::string _master_secret;
      // secure random number generator
      csprng _secure_random;
      // time of expiration
        boost::posix_time::ptime _client_expireTime;
        boost::posix_time::ptime _master_startTime;
      // this shall be moved
        std::map < int32_t, amcl::octet > _key_store;

    };
  }
}
#endif
