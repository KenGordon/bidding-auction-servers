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
#include "core/utils/src/base64.h"
#include "glog/logging.h"
#include "gtest/gtest.h"
#include "public/cpio/interface/cpio.h"
#include "quiche/common/quiche_random.h"
#include "quiche/oblivious_http/oblivious_http_client.h"
#include "src/core/lib/event_engine/default_event_engine.h"
#include "src/cpp/accesstoken/src/accesstoken_fetcher_manager.h"
#include "src/cpp/concurrent/event_engine_executor.h"

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

using google::scp::core::utils::Base64Decode;
using ::google::scp::cpio::Cpio;
using ::google::scp::cpio::CpioOptions;
using ::google::scp::cpio::LogOption;
using ::testing::HasSubstr;
// using PlatformJwtServiceEndpointMap =
//     absl::flat_hash_map<CloudPlatform,
//                         google::scp::cpio::AccessTokenServiceEndpoint>;
/**
std::unique_ptr<server_common::AccessTokenFetcherInterface>
CreateKeyFetcherManager(
    std::unique_ptr<server_common::PublicKeyFetcherInterface>
        public_key_fetcher,
    const unsigned int private_key_cache_ttl_seconds =
        kDefaultPrivateKeyCacheTtlSeconds,
    const unsigned int key_refresh_flow_run_frequency_seconds =
        kDefaultKeyRefreshFlowRunFrequencySeconds) {
  google::scp::cpio::PrivateKeyVendingEndpoint primary, secondary;
  // AZURE_TODO: We might have to specify more fields for primary, secondary.
  //             See services/common/encryption/key_fetcher_factory.cc for what
  //             the original code does

  primary.private_key_vending_service_endpoint =
      absl::GetFlag(FLAGS_client_secret);
  // AZURE_TODO: make it a command line option
  absl::Duration private_key_ttl = absl::Seconds(private_key_cache_ttl_seconds);
  std::unique_ptr<server_common::PrivateKeyFetcherInterface>
      private_key_fetcher = server_common::PrivateKeyFetcherFactory::Create(
          primary, {secondary}, private_key_ttl);

  absl::Duration key_refresh_flow_run_freq =
      absl::Seconds(key_refresh_flow_run_frequency_seconds);

  auto event_engine = std::make_unique<server_common::EventEngineExecutor>(
      grpc_event_engine::experimental::CreateEventEngine());
  std::unique_ptr<server_common::KeyFetcherManagerInterface> manager =
      server_common::KeyFetcherManagerFactory::Create(
          key_refresh_flow_run_freq, std::move(public_key_fetcher),
          std::move(private_key_fetcher), std::move(event_engine));
  manager->Start();

  return manager;
}
*/
/**
// Based on services/common/encryption/key_fetcher_factory.cc
std::unique_ptr<server_common::PublicKeyFetcherInterface>
CreatePublicKeyFetcher() {
  std::vector<std::string> endpoint = {
      absl::GetFlag(FLAGS_aad_endpoint)};
//"client_id=$ClientApplicationId&client_secret=$ClientSecret&scope=$ApiIdentifierUri/.default&grant_type=client_credentials"
  std::vector<std::string> clientId = {
      absl::GetFlag(FLAGS_client_application_id)};

  std::vector<std::string> clientSecret = {
      absl::GetFlag(FLAGS_client_secret)};

  std::vector<std::string> scope = {
      absl::GetFlag(FLAGS_api_identifier_uri)};

  server_common::CloudPlatform cloud_platform =
      server_common::CloudPlatform::AZURE;

  PlatformJwtServiceEndpointMap per_platform_endpoints = {
      {cloud_platform, endpoint}};
  return server_common::PublicKeyFetcherFactory::Create(per_platform_endpoints);
}


absl::StatusOr<quiche::ObliviousHttpRequest> EncryptAndDecrypt(
    std::unique_ptr<server_common::KeyFetcherManagerInterface>
        key_fetcher_manager,
    const std::string plaintext_payload) {
  // AZURE_TODO: There should be a function to select proper value. We can add
  // an assertion to check the value is AZURE.
  server_common::CloudPlatform cloud_platform =
      server_common::CloudPlatform::AZURE;
  auto public_key = key_fetcher_manager->GetPublicKey(cloud_platform);
  EXPECT_TRUE(public_key.ok());

  const absl::StatusOr<uint8_t> key_id =
      ToIntKeyId(public_key.value().key_id());
  EXPECT_TRUE(key_id.ok());

  const auto config =
      GetOhttpKeyConfig(key_id.value(), EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);

  std::string decoded_public_key;
  Base64Decode(public_key.value().public_key(), decoded_public_key);

  const auto request =
      quiche::ObliviousHttpRequest::CreateClientObliviousRequest(
          plaintext_payload, decoded_public_key, config);
  const std::string payload_bytes = request->EncapsulateAndSerialize();

  std::optional<server_common::PrivateKey> private_key =
      key_fetcher_manager->GetPrivateKey(std::to_string(key_id.value()));
  EXPECT_TRUE(private_key.has_value());

  return server_common::DecryptEncapsulatedRequest(private_key.value(),
                                                   payload_bytes);
}

class KmsInstance {
 public:
  KmsInstance() {
    std::string aad_endpoint = absl::GetFlag(FLAGS_aad_endpoint);
    child_pid_ = fork();

    CHECK(child_pid_ != -1) << "Fork failed.";

    if (child_pid_ == 0) {
      setpgid(0, 0);
      int result = system(aad_endpoint.c_str());
    }
  }

  ~KmsInstance() {
    int result = kill(-child_pid_, SIGTERM);
    CHECK(result == 0) << "Failed to kill KMS.";
  }

  void CreateKeyPair() {
    std::string api_identifier_uri =
        absl::GetFlag(FLAGS_api_identifier_uri);
    int result = system(api_identifier_uri.c_str());
    CHECK(result == 0) << "Failed to create a key pair.";
  }

 private:
  pid_t child_pid_;
};
*/
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
};

TEST_F(AccessTokenTest, RetrieveAccessTokenSuccess) {
  // This test case is to demonstrate how to retrieve an accesstoken

  privacy_sandbox::server_common::AccessTokenClientOptions tokenOptions;
  tokenOptions.endpoint = "your_endpoint";
  tokenOptions.clientid = "your_client_id";
  tokenOptions.clientSecret = "your_client_secret";
  tokenOptions.apiUri = "your_api_uri";

  auto accesstoken_fetcher_manager =
      privacy_sandbox::server_common::AccessTokenClientFactory::Create(tokenOptions);
}

}  // namespace
}  // namespace privacy_sandbox::aad_accesstoken

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
