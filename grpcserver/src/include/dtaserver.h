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
#ifndef DTA_SERVER_IMPL
#define DTA_SERVER_IMPL
#include <string>
#include <memory>
#include <array>
#include <optional>
#include <map>
#include <proto-generated/dta.grpc.pb.h>
#include <amcl/amcl.h>
#include <amcl/ecdh_support.h>	// for hmac
#include <secret_proxy.h>

namespace milagro
{
  namespace dta
  {
    using namespace grpc;

    struct client_signature_ctx
    {
      std::string client_secret;
      int32_t appId;
        std::string hash_mpin_hex;
        std::string hash_user_id;
        google::protobuf::Timestamp expires;
    };

    class dta_server final:public DtaService::Service
    {
    public:
      ::grpc::Status GetClientSecret (ServerContext * context,
				      const AuthClientSecretRequest * request,
				      AuthServerResponse * response) override;
      ::grpc::Status GetServerSecret (ServerContext * context,
				      const AuthServerSecretRequest * request,
				      AuthServerResponse * response) override;
      ::grpc::Status GetStatus (ServerContext * context,
				const StatusRequest * request,
				StatusResponse * response) override;
      ::grpc::Status GetTimePermit (ServerContext * context,
				    const TimePermitRequest * request,
				    TimePermitResponse * response) override;
      ::grpc::Status GetTimePermits (ServerContext * context,
				     const::milagro::dta::TimePermitsRequest *
				     request,
				     TimePermitsResponse * response) override;
    private:

        amcl::
	octet make_client_content (const client_signature_ctx & content);
        amcl::
	octet make_server_signature_data (const AuthServerSecretRequest *
					  request);
        amcl::octet make_time_content (const client_signature_ctx & content);
        std::string hmac_sign_message (const boost::posix_time::ptime &
				       timestamp,
				       const amcl::octet & secret,
				       const amcl::octet & key);
        std::string hmac_client_sign (const client_signature_ctx & content,
				      const amcl::octet & key);
      ::grpc::Status hmac_verify (std::string request_signature,
				  amcl::octet request_content,
				  std::optional < amcl::octet > key);

        std::optional < amcl::octet > getCredential (int key) const;
        std::unique_ptr < milagro::secure_store::secret_proxy > _key_store;
      csprng _secure_random;
    };
  }
}
#endif
