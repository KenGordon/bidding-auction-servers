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

#include <gmock/gmock-matchers.h>
#include <include/gmock/gmock-actions.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/escaping.h"
#include "absl/synchronization/blocking_counter.h"
#include "absl/synchronization/notification.h"
#include "core/curl_client/src/http1_curl_client.h"
#include "core/utils/src/base64.h"
#include "cpio/client_providers/global_cpio/src/global_cpio.h"
#include "glog/logging.h"
#include "gtest/gtest.h"
#include "public/cpio/interface/cpio.h"
#include "quiche/common/quiche_random.h"
#include "quiche/oblivious_http/oblivious_http_client.h"
#include "scp/cc/core/curl_client/src/http1_curl_wrapper.h"
#include "src/core/lib/event_engine/default_event_engine.h"
#include "src/cpp/accesstoken/src/accesstoken_fetcher_manager.h"
#include "src/cpp/concurrent/event_engine_executor.h"
constexpr absl::Duration kRequestTimeout = absl::Seconds(10);

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

namespace privacy_sandbox::aad_accesstoken {
enum class CloudPlatform {
  LOCAL,
  GCP,
  AWS,
  AZURE,
};
namespace {

static constexpr char kPlaintextPayload[] = "plaintext";
// 45 days. Value for private_key_cache_ttl_seconds in
// services/common/constants/common_service_flags.cc
static constexpr unsigned int kDefaultPrivateKeyCacheTtlSeconds = 3888000;
// 3 hours. Value for key_refresh_flow_run_frequency_seconds in
// services/common/constants/common_service_flags.cc
static constexpr unsigned int kDefaultKeyRefreshFlowRunFrequencySeconds = 10800;

using google::scp::core::AsyncContext;
using google::scp::core::Http1CurlClient;
using google::scp::core::HttpRequest;
using google::scp::core::HttpResponse;
using google::scp::core::utils::Base64Decode;
using ::google::scp::cpio::Cpio;
using ::google::scp::cpio::CpioOptions;
using ::google::scp::cpio::LogOption;
using google::scp::cpio::client_providers::GlobalCpio;
using ::testing::HasSubstr;

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
  server_common::GrpcInit grpc_init_;
  std::shared_ptr<Http1CurlClient> http_client_;
};

/// @brief Make a REST API request
/// @param http_client client used to do the request
/// @param method 
/// @param url 
/// @param headers 
/// @return 
std::tuple<google::scp::core::ExecutionResult, std::string, int> MakeRequest(
    google::scp::core::HttpClientInterface& http_client,
    const std::string& url,
    google::scp::core::HttpMethod method = google::scp::core::HttpMethod::GET, 
    const absl::btree_multimap<std::string, std::string>& headers = {}) {
  auto request = std::make_shared<HttpRequest>();
  request->method = method;
  request->path = std::make_shared<std::string>(url);
  if (!headers.empty()) {
    request->headers =
        std::make_shared<google::scp::core::HttpHeaders>(headers);
  }
  google::scp::core::ExecutionResult context_result;
  absl::Notification finished;
  std::string body = "";
  int status_code = 404;
  AsyncContext<HttpRequest, HttpResponse> context(
      std::move(request),
      [&](AsyncContext<HttpRequest, HttpResponse>& context) {
        context_result = context.result;
        if (context.response) {
          status_code = static_cast<int>(context.response->code);
          if (status_code < 300) {
            const auto& bytes = *context.response->body.bytes;
            body = std::string(bytes.begin(), bytes.end());
          }
        }
        finished.Notify();
      });

  auto result = http_client.PerformRequest(context, kRequestTimeout);

  finished.WaitForNotification();

  // Return the response
  return {context_result, body, status_code};
}

TEST_F(AccessTokenTest, SimpleRestCallSuccess) {
  // This test case is to demonstrate how to call a rest api
  // Declare a shared pointer to an HttpClientInterface
  std::shared_ptr<google::scp::core::HttpClientInterface> http_client;

  // Attempt to get the Http1Client from the GlobalCpio
  auto client = GlobalCpio::GetGlobalCpio()->GetHttp1Client(http_client);

  // Check if the operation was successful
  if (!client.Successful()) {
    // If not successful, print an error message and return from the function
    std::cout << "[ FAILURE ] Unable to get Http Client." << std::endl
              << std::endl;
    return;
  }

  http_client->Init();
  http_client->Run();
  auto [response, body, status_code] =
      MakeRequest(*http_client,
                  "https://cat-fact.herokuapp.com/facts/random?amount=1");
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

  privacy_sandbox::server_common::AccessTokenClientOptions tokenOptions;
  tokenOptions.endpoint = "your_endpoint";
  tokenOptions.clientid = "your_client_id";
  tokenOptions.clientSecret = "your_client_secret";
  tokenOptions.apiUri = "your_api_uri";

  auto accesstoken_fetcher_manager =
      privacy_sandbox::server_common::AccessTokenClientFactory::Create(
          tokenOptions);

  // Declare a shared pointer to an HttpClientInterface
  std::shared_ptr<google::scp::core::HttpClientInterface> http_client;

  // Attempt to get the Http1Client from the GlobalCpio
  auto client = GlobalCpio::GetGlobalCpio()->GetHttp1Client(http_client);

  // Check if the operation was successful
  if (!client.Successful()) {
    // If not successful, print an error message and return from the function
    std::cout << "[ FAILURE ] Unable to get Http Client." << std::endl
              << std::endl;
    return;
  }

  http_client->Init();
  http_client->Run();
  auto [response, body, status_code] =
      MakeRequest(*http_client,
                  "https://cat-fact.herokuapp.com/facts/random?amount=1");
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

}  // namespace
}  // namespace privacy_sandbox::aad_accesstoken

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
