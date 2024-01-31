// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdlib>
#include <memory>
#include <utility>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "cpio/client_providers/global_cpio/src/global_cpio.h"
#include "glog/logging.h"
#include "gtest/gtest.h"
#include "public/cpio/interface/cpio.h"
#include "src/cpp/accesstoken/src/accesstoken_fetcher_manager.h"

ABSL_FLAG(std::string, aad_endpoint,
          "https://login.microsoftonline.com/"
          "afcc81fd-382e-4c87-9f7e-9fdd934dfd9b/oauth2/v2.0/token",
          "URL of AAD tenant");

ABSL_FLAG(std::string, api_identifier_uri,
          "api://d538182b-fc13-4cf2-a5a5-946db26caef3", "API URI");

ABSL_FLAG(std::string, api_application_id,
          "d538182b-fc13-4cf2-a5a5-946db26caef3", "API client id");

ABSL_FLAG(std::string, client_application_id,
          "4dcf9615-265c-40e9-93d4-728fbe1d1857", "Application client id");

ABSL_FLAG(std::string, client_secret, "provide_client_secret", "Client secret");

namespace {

using ::google::scp::cpio::Cpio;
using ::google::scp::cpio::CpioOptions;
using ::google::scp::cpio::LogOption;
using google::scp::cpio::client_providers::GlobalCpio;

class AccessTokenTest : public testing::Test {
 protected:
  void SetUp() override {
    // Init Cpio
    cpio_options_.log_option = google::scp::cpio::LogOption::kConsoleLog;
    CHECK(google::scp::cpio::Cpio::InitCpio(cpio_options_).Successful())
        << "Failed to initialize CPIO library";
  }
  void TearDown() override {
    google::scp::cpio::Cpio::ShutdownCpio(cpio_options_);
  }

  google::scp::cpio::CpioOptions cpio_options_;
  // Initialize and shutdown gRPC client. DO NOT REMOVE.
};

TEST_F(AccessTokenTest, GetAccessTokenSuccess) {
    // This test case is to demonstrate how to retrieve an accesstoken via GetAccessToken

  // Declare a shared pointer to an HttpClientInterface
  std::shared_ptr<google::scp::core::HttpClientInterface> http_client;

  // Attempt to get the Http1Client from the GlobalCpio
  GlobalCpio::GetGlobalCpio()->GetHttp1Client(http_client);

  // Create an AccessTokenClientOptions instance and set its properties
  privacy_sandbox::server_common::AccessTokenClientOptions tokenOptions;
  tokenOptions.endpoint = absl::GetFlag(FLAGS_aad_endpoint);
  tokenOptions.clientid = absl::GetFlag(FLAGS_client_application_id);
  tokenOptions.clientSecret = absl::GetFlag(FLAGS_client_secret);
  tokenOptions.apiApplicationId = absl::GetFlag(FLAGS_api_application_id);

  // Create an AccessTokenFetcherManager instance
  auto accesstoken_fetcher_factory =
      privacy_sandbox::server_common::AccessTokenClientFactory::Create(
          tokenOptions, http_client);
  auto [response, body, status_code] = accesstoken_fetcher_factory->GetAccessToken();

  // Check the response
  if (status_code < 300) {
    std::cout << "Response body: " << body << std::endl;
    std::cout << "Status code: " << status_code << std::endl;
  } else {
    std::cout << "[ FAILURE ] Unexpected status code: " << status_code
              << std::endl;
  }

  // Check the result
  ASSERT_TRUE(response.Successful());
  ASSERT_GT(body.length(), 0);
  ASSERT_EQ(status_code, 200);
}

TEST_F(AccessTokenTest, RetrieveAccessTokenSuccess) {
    // This test case is to demonstrate how to retrieve an accesstoken

  // Declare a shared pointer to an HttpClientInterface
  std::shared_ptr<google::scp::core::HttpClientInterface> http_client;

  // Attempt to get the Http1Client from the GlobalCpio
  GlobalCpio::GetGlobalCpio()->GetHttp1Client(http_client);

  // Create an AccessTokenClientOptions instance and set its properties
  privacy_sandbox::server_common::AccessTokenClientOptions tokenOptions;
  tokenOptions.endpoint = "your_endpoint";
  tokenOptions.clientid = absl::GetFlag(FLAGS_client_application_id);
  tokenOptions.clientSecret = absl::GetFlag(FLAGS_client_secret);
  tokenOptions.apiApplicationId = absl::GetFlag(FLAGS_api_application_id);

  // Set http header
  absl::btree_multimap<std::string, std::string> headers;
  headers.insert(std::make_pair("Content-Type", "application/x-www-form-urlencoded"));

  //std::string request_body = "client_id=4dcf9615-265c-40e9-93d4-728fbe1d1857&client_secret=85k8Q~k-rMytUNlQQQtF3zneNNY5B8hcl5b2Dckx&scope=api://d538182b-fc13-4cf2-a5a5-946db26caef3/.default&grant_type=client_credentials";
  std::ostringstream request_body_stream;
  request_body_stream << "client_id=" << absl::GetFlag(FLAGS_client_application_id)
                      << "&client_secret=" << absl::GetFlag(FLAGS_client_secret)
                      << "&scope=" << absl::GetFlag(FLAGS_api_application_id) << "/.default"
                      << "&grant_type=client_credentials";
  std::string request_body = request_body_stream.str();
  std::cout << "Request Body: " << request_body << std::endl;
  std::cout << "URL: " << absl::GetFlag(FLAGS_aad_endpoint) << std::endl;

  // Create an AccessTokenFetcherManager instance
  auto accesstoken_fetcher_factory =
      privacy_sandbox::server_common::AccessTokenClientFactory::Create(
          tokenOptions, http_client);
  auto [response, body, status_code] = accesstoken_fetcher_factory->MakeRequest(
      absl::GetFlag(FLAGS_aad_endpoint),
      google::scp::core::HttpMethod::POST,
      headers,
      request_body
    );

  // Check the response
  if (status_code < 300) {
    std::cout << "Response body: " << body << std::endl;
    std::cout << "Status code: " << status_code << std::endl;
  } else {
    std::cout << "[ FAILURE ] Unexpected status code: " << status_code
              << std::endl;
  }

  // Check the result
  ASSERT_TRUE(response.Successful());
  ASSERT_GT(body.length(), 0);
  ASSERT_EQ(status_code, 200);
}

TEST_F(AccessTokenTest, SimpleRestCallSuccess) {
  // This test case is to demonstrate how to call a rest api

  // Declare a shared pointer to an HttpClientInterface
  std::shared_ptr<google::scp::core::HttpClientInterface> http_client;

  // Attempt to get the Http1Client from the GlobalCpio
  GlobalCpio::GetGlobalCpio()->GetHttp1Client(http_client);

  // Create an AccessTokenClientOptions instance and set its properties
  privacy_sandbox::server_common::AccessTokenClientOptions tokenOptions;
  tokenOptions.endpoint = "your_endpoint";
  tokenOptions.clientid = "your_client_id";
  tokenOptions.clientSecret = "your_client_secret";
  tokenOptions.apiApplicationId = "your_api_uri";

  // Create an AccessTokenFetcherManager instance
  auto accesstoken_fetcher_factory =
      privacy_sandbox::server_common::AccessTokenClientFactory::Create(
          tokenOptions, http_client);
  auto [response, body, status_code] = accesstoken_fetcher_factory->MakeRequest(
      "https://cat-fact.herokuapp.com/facts/random?amount=1");

  // Check the response
  if (status_code < 300) {
    std::cout << "Response body: " << body << std::endl;
    std::cout << "Status code: " << status_code << std::endl;
  } else {
    std::cout << "[ FAILURE ] Unexpected status code: " << status_code
              << std::endl;
  }

  // Check the result
  ASSERT_TRUE(response.Successful());
  ASSERT_GT(body.length(), 0);
  ASSERT_EQ(status_code, 200);
}

}  // namespace privacy_sandbox::aad_accesstoken

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  for (int i = 0; i < argc; ++i) {
    std::cout << "argv[" << i << "]: " << argv[i] << std::endl;
  }

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
