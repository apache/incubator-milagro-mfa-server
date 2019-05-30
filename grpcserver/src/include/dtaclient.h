#ifndef DTA_CLIENT_H
#define DTA_CLIENT_H
#include <string>
#include <proto-generated/dta.pb.h>

namespace milagro
{

  namespace dta
  {

    class dta_client
    {
    public:
      dta_client (const std::string & dtaEndpoint)
      {
      }
      std::string get_client_secret (const milagro::dta::
				     AuthClientSecretRequest & request)
      {
	return "829392389";
      }
    };
  }
}
#endif
