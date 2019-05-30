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
#include <dtaserver.h>
#include <iostream>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>

using namespace grpc;
using
  grpc::Server;
using
  grpc::ServerBuilder;
using
  grpc::ServerContext;
using
  grpc::Status;

void
RunServer (const std::string & address)
{
  std::string server_address (address);
  milagro::dta::dta_server dataService;
  ServerBuilder
    builder;
  builder.AddListeningPort (server_address,
			    grpc::InsecureServerCredentials ());
  builder.RegisterService (&dataService);
  std::unique_ptr < Server > server (builder.BuildAndStart ());
  std::cout << "Server listening on " << server_address << std::endl;
  server->Wait ();
}

int
main ()
{
  RunServer ("0.0.0.0:14100");
  return 0;
}
