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
#include <sstream>
#include <dtaserver.h>
#include <utils.h>
#include <google/protobuf/util/time_util.h>

namespace milagro
{
  namespace dta
  {

    namespace util = milagro::utils;
    using namespace grpc;
    using namespace google::protobuf::util;

    ::grpc::Status dta_server::GetClientSecret (ServerContext * context,
						const
						AuthClientSecretRequest *
						request,
						AuthServerResponse * response)
    {
      auto app_id = request->appid ();
      auto expires = request->expiretime ();
      auto signature = request->hmacsignature ();
      auto hash_mpin_hex = request->mpinidhexencoded ();
      auto hash_user_id = request->hashuserid ();
      auto provided_signature = request->hmacsignature ();
      // concat the needed data to verify
      if ((app_id == 0) || provided_signature.empty ())
	{
	  response->set_responsemessage ("Invalid Parameter calls");
	  return::grpc::Status (StatusCode::INVALID_ARGUMENT,
				"Signature and appId shall be present");
	}

      if ((hash_user_id.size () != 0) && (hash_mpin_hex.size () != 64))
	{
	  response->set_responsemessage ("Invalid MPIN Parameter");
	  return::grpc::Status::CANCELLED;
	}
      auto key = getCredential (app_id);
      if (!key.has_value ())
	{
	  response->set_statuscode (milagro::dta::ResultCode::PROTOCOL_ERROR);
	  return::grpc::Status (StatusCode::INVALID_ARGUMENT,
				"The key associated to the app should be present");
	}

      client_signature_ctx client_content;
      client_content.appId = app_id;
      client_content.hash_mpin_hex = hash_mpin_hex;
      client_content.hash_user_id = hash_user_id;
      client_content.expires = expires;
      auto request_content = make_client_content (client_content);

      if (!hmac_verify (provided_signature, request_content, key).ok ())
	{
	  response->
	    set_statuscode (milagro::dta::ResultCode::INVALID_SIGNATURE);
	  return::grpc::Status (StatusCode::PERMISSION_DENIED,
				"Invalid signature");
	}
      std::string client_secret;
      try
      {
	client_secret =
	  util::octet_to_string (_key_store->generate_client_secret
				 (hash_user_id, hash_mpin_hex));
      }
      catch (std::exception & ex)
      {
	response->
	  set_statuscode (milagro::dta::ResultCode::KEY_GENERATION_FAILED);
	response->set_responsemessage (ex.what ());
	return::grpc::Status (StatusCode::INTERNAL, ex.what ());
      }

      client_signature_ctx params;
      params.appId = app_id;
      params.client_secret = client_secret;
      params.hash_mpin_hex = hash_mpin_hex;
      params.hash_user_id = hash_user_id;
      params.expires = expires;
      std::string client_signature;
      try
      {
	client_signature = hmac_client_sign (params, key.value ());
      }
      catch (const std::exception & e)
      {
	std::cerr << e.what () << '\n';
      }
      response->set_statuscode (milagro::dta::ResultCode::SUCCESS);
      response->set_secret (client_secret);
      response->set_hmacsignature (client_signature);
      return::grpc::Status::OK;
    }
    ::grpc::Status dta_server::GetStatus (ServerContext * context,
					  const StatusRequest * request,
					  StatusResponse * response)
    {
    }
    ::grpc::Status dta_server::GetServerSecret (ServerContext * context,
						const
						AuthServerSecretRequest *
						request,
						AuthServerResponse * response)
    {
      auto appId = request->appid ();
      auto key = getCredential (appId);
      auto signature = request->hmacsignature ();
      if (!key.has_value ())
	{
	  response->set_statuscode (milagro::dta::ResultCode::PROTOCOL_ERROR);
	  return::grpc::Status (StatusCode::INVALID_ARGUMENT,
				"The application should be registered");
	}
      auto request_content = make_server_signature_data (request);
      if (hmac_verify (signature, request_content, key).ok ())
	{
	  response->
	    set_statuscode (milagro::dta::ResultCode::INVALID_SIGNATURE);
	  return::grpc::Status (StatusCode::PERMISSION_DENIED,
				"Invalid signature");
	}
      std::string masterHexKey;
      // success.
      amcl::octet masterKey;
      try
      {
	masterKey = _key_store->generate_master_secret ();
	masterHexKey = util::octet_to_string (masterKey);
      }
      catch (std::exception & store_ex)
      {
	response->
	  set_statuscode (milagro::dta::ResultCode::KEY_GENERATION_FAILED);
	response->set_responsemessage (store_ex.what ());
	return::grpc::Status (StatusCode::ABORTED, "Key generation failed");
      }
      auto master_signature =
	hmac_sign_message (_key_store->server_key_start (),
			   masterKey, key.value ());
      response->set_secret (masterHexKey);
      response->set_hmacsignature (master_signature);
      return::grpc::Status::OK;
    }
    ::grpc::Status dta_server::GetTimePermit (ServerContext * context,
					      const TimePermitRequest *
					      request,
					      TimePermitResponse * response)
    {
      auto appId = request->appid ();
      auto key = getCredential (appId);
      if (!key.has_value ())
	{
	  response->set_statuscode (milagro::dta::ResultCode::PROTOCOL_ERROR);
	  return::grpc::Status (StatusCode::INVALID_ARGUMENT,
				"An app identifier shall be registered");
	}
      auto hash_mpin_id_hex = request->mpinidhexencoded ();
      auto provided_signature = request->hmacsignature ();
      auto app_id = request->appid ();
      client_signature_ctx client_content;
      client_content.appId = app_id;
      client_content.hash_mpin_hex = hash_mpin_id_hex;
      auto request_content = make_time_content (client_content);

      if (!hmac_verify (provided_signature, request_content, key).ok ())
	{
	  response->
	    set_statuscode (milagro::dta::ResultCode::INVALID_SIGNATURE);
	  return::grpc::Status (StatusCode::PERMISSION_DENIED,
				"Invalid signature");
	}
      auto timepermit = _key_store->get_time_permits (hash_mpin_id_hex, 1);
      response->set_timepermit (timepermit[0]);
      response->set_statuscode (milagro::dta::ResultCode::SUCCESS);
      return::grpc::Status::OK;
    }

    ::grpc::Status dta_server::GetTimePermits (ServerContext * context,
					       const::milagro::
					       dta::TimePermitsRequest *
					       request,
					       TimePermitsResponse * response)
    {

      auto appId = request->appid ();
      auto count = request->count ();

      auto key = getCredential (appId);
      if (!key.has_value ())
	{
	  response->set_statuscode (milagro::dta::ResultCode::PROTOCOL_ERROR);
	  return::grpc::Status (StatusCode::INVALID_ARGUMENT,
				"Application not registered");
	}
      auto hash_mpin_id_hex = request->mpinidhexencoded ();
      auto provided_signature = request->hmacsignature ();
      client_signature_ctx time_content;
      time_content.appId = appId;
      time_content.hash_mpin_hex = hash_mpin_id_hex;
      auto request_content = make_time_content (time_content);
      auto timepermits =
	_key_store->get_time_permits (hash_mpin_id_hex, count);
      return::grpc::Status::OK;
    }
    std::optional < amcl::octet > dta_server::getCredential (int key) const
    {
      return _key_store->search_key (key);
    }
    amcl::octet dta_server::make_server_signature_data (const
							AuthServerSecretRequest
							* request)
    {
      amcl::octet signature;
      std::ostringstream buffer;

      return signature;
    }
    amcl::octet dta_server::make_client_content (const client_signature_ctx &
						 content)
    {
      amcl::octet client_content;
      return client_content;
    }
    std::string dta_server::hmac_client_sign (const client_signature_ctx &
					      content,
					      const amcl::octet & key)
    {
      amcl::octet data = make_client_content (content);
      int olen = 32;
      amcl::octet hmac;
      /* this is a library design problem. 
         i would never expect in C++ to do a const_cast
       */
      amcl::HMAC (SHA256, &data, const_cast < amcl::octet * >(&key),
		  olen, &hmac);
      auto value = util::octet_to_string (hmac);
      return value;
    }

    amcl::octet dta_server::make_time_content (const client_signature_ctx &
					       content)
    {
      amcl::octet octect;
      return octect;
    }

    std::string dta_server::hmac_sign_message (const boost::
					       posix_time::ptime & timestamp,
					       const amcl::octet & secret,
					       const amcl::octet & key)
    {
      std::ostringstream buffer;
      amcl::octet hmac;
      amcl::octet inputdata;
      char input[1024];
      amcl::octet input_data =
      {
      0, sizeof (input), input};
      int olen = 32;
      std::strncpy (input, buffer.str ().c_str (), sizeof (input));
      input[sizeof (input) - 1] = 0;
      input_data.len = std::strlen (input);

      amcl::HMAC (SHA256,
		  &input_data,
		  const_cast < amcl::octet * >(&key), olen, &hmac);
      return util::octet_to_string (hmac);
    }
    ::grpc::Status dta_server::hmac_verify (std::string request_signature,
					    amcl::octet request_content,
					    std::optional < amcl::octet > key)
    {

      int olen = 32;
      amcl::octet hmac;
      amcl::HMAC (SHA256, &request_content, &key.value (), olen, &hmac);
      std::string result = milagro::utils::octet_to_string (hmac);

      if (result.compare (request_signature))
	{
	  return::grpc::Status (StatusCode::INVALID_ARGUMENT,
				"Invalid signature");
	}
      return::grpc::Status::OK;
    }
  }				// namespace dta
}				// namespace milagro
