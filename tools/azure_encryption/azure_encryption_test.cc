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
#include "gtest/gtest.h"
#include "public/cpio/interface/cpio.h"
#include "quiche/common/quiche_random.h"
#include "quiche/oblivious_http/oblivious_http_client.h"
#include "src/core/lib/event_engine/default_event_engine.h"
#include "src/cpp/communication/ohttp_utils.h"
#include "src/cpp/concurrent/event_engine_executor.h"
#include "src/cpp/encryption/key_fetcher/src/fake_key_fetcher_manager.h"

ABSL_FLAG(std::string, kms_startup_command, "provide_kms_startup_command",
          "Command to start up KMS. KMS should be able to killed using the pid "
          "of the command.");

ABSL_FLAG(std::string, kms_create_key_command, "provide_kms_create_key_command",
          "Command to create a key pair in KMS.");

ABSL_FLAG(std::string, public_key_endpoint,
          "https://127.0.0.1:8000/app/listpubkeys",
          "Endpoint serving set of public keys used for encryption");

ABSL_FLAG(std::string, primary_coordinator_private_key_endpoint,
          "https://127.0.0.1:8000/app/key?fmt=tink",
          "Primary coordinator's private key vending service endpoint");

namespace privacy_sandbox::azure_encryption {
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
using PlatformToPublicKeyServiceEndpointMap = absl::flat_hash_map<
    server_common::CloudPlatform,
    std::vector<google::scp::cpio::PublicKeyVendingServiceEndpoint>>;

// This function is redundant considering the usage, but
// should be useful to know how bytes are handled in privacy sandbox code base.
std::string GetTestHpkePrivateKey() {
  const std::string hpke_key_hex =
      "b77431ecfa8f4cfc30d6e467aafa06944dffe28cb9dd1409e33a3045f5adc8a1";
  return absl::HexStringToBytes(hpke_key_hex);
}

std::string GetTestHpkePublicKey() {
  const std::string public_key =
      "6d21cfe09fbea5122f9ebc2eb2a69fcc4f06408cd54aac934f012e76fcdcef62";
  return absl::HexStringToBytes(public_key);
}

const quiche::ObliviousHttpHeaderKeyConfig GetOhttpKeyConfig(uint8_t key_id,
                                                             uint16_t kem_id,
                                                             uint16_t kdf_id,
                                                             uint16_t aead_id) {
  const auto ohttp_key_config = quiche::ObliviousHttpHeaderKeyConfig::Create(
      key_id, kem_id, kdf_id, aead_id);
  EXPECT_TRUE(ohttp_key_config.ok());
  return std::move(ohttp_key_config.value());
}

// Copied from unnamed namespace in
// data-plane-shared-libraries/src/cpp/communication/ohttp_utils.cc
absl::StatusOr<uint8_t> ToIntKeyId(absl::string_view key_id) {
  uint32_t val;
  if (!absl::SimpleAtoi(key_id, &val) ||
      val > std::numeric_limits<uint8_t>::max()) {
    return absl::InternalError(
        absl::StrCat("Cannot parse OHTTP key ID from: ", key_id));
  }

  return val;
}

// Based on services/common/encryption/key_fetcher_factory.cc
std::unique_ptr<server_common::PublicKeyFetcherInterface>
CreatePublicKeyFetcher() {
  std::vector<std::string> endpoints = {
      absl::GetFlag(FLAGS_public_key_endpoint)};

  server_common::CloudPlatform cloud_platform =
      server_common::CloudPlatform::kAzure;

  PlatformToPublicKeyServiceEndpointMap per_platform_endpoints = {
      {cloud_platform, endpoints}};
  return server_common::PublicKeyFetcherFactory::Create(per_platform_endpoints);
}

// Based on services/common/encryption/key_fetcher_factory.cc
std::unique_ptr<server_common::KeyFetcherManagerInterface>
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
      absl::GetFlag(FLAGS_primary_coordinator_private_key_endpoint);
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

absl::StatusOr<quiche::ObliviousHttpRequest> EncryptAndDecrypt(
    std::unique_ptr<server_common::KeyFetcherManagerInterface>
        key_fetcher_manager,
    const std::string plaintext_payload) {
  // AZURE_TODO: There should be a function to select proper value. We can add
  // an assertion to check the value is AZURE.
  server_common::CloudPlatform cloud_platform =
      server_common::CloudPlatform::kAzure;
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

  const auto label_for_test = server_common::kBiddingAuctionOhttpResponseLabel;
  const auto request =
      quiche::ObliviousHttpRequest::CreateClientObliviousRequest(
          plaintext_payload, decoded_public_key, config, label_for_test);
  const std::string payload_bytes = request->EncapsulateAndSerialize();

  std::optional<server_common::PrivateKey> private_key =
      key_fetcher_manager->GetPrivateKey(std::to_string(key_id.value()));
  EXPECT_TRUE(private_key.has_value());

  server_common::EncapsulatedRequest encapsulatedRequest = {payload_bytes,
                                                            label_for_test};

  return server_common::DecryptEncapsulatedRequest(private_key.value(),
                                                   encapsulatedRequest);
}

class KmsInstance {
 public:
  KmsInstance() {
    std::string kms_startup_command = absl::GetFlag(FLAGS_kms_startup_command);
    child_pid_ = fork();

    CHECK(child_pid_ != -1) << "Fork failed.";

    if (child_pid_ == 0) {
      setpgid(0, 0);
      int result = system(kms_startup_command.c_str());
    }
  }

  ~KmsInstance() {
    int result = kill(-child_pid_, SIGTERM);
    CHECK(result == 0) << "Failed to kill KMS.";
  }

  void CreateKeyPair() {
    std::string kms_create_key_command =
        absl::GetFlag(FLAGS_kms_create_key_command);
    int result = system(kms_create_key_command.c_str());
    CHECK(result == 0) << "Failed to create a key pair.";
  }

 private:
  pid_t child_pid_;
};

class EncryptionTest : public testing::Test {
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

TEST_F(EncryptionTest,
       DecryptEncapsulatedRequestWithFakeKeyFetcherManagerSuccess) {
  // This test case is to demonstrate how to use key_fetcher_manager interface
  // rather than to test azure implementation

  // OHTTP key ID
  const uint8_t test_key_id = 5;
  auto key_fetcher_manager =
      std::make_unique<server_common::FakeKeyFetcherManager>(
          absl::BytesToHexString(GetTestHpkePublicKey()),
          absl::BytesToHexString(GetTestHpkePrivateKey()),
          std::to_string(test_key_id));

  const std::string plaintext_payload = kPlaintextPayload;
  const auto decrypted_result =
      EncryptAndDecrypt(std::move(key_fetcher_manager), plaintext_payload);
  EXPECT_EQ(decrypted_result->GetPlaintextData(), plaintext_payload);
}

TEST_F(
    EncryptionTest,
    DecryptEncapsulatedRequestWithFakeKeyFetcherManagerBadPrivateKeyFailure) {
  // This test case is to check tests in this file are valid rather than to test
  // azure implementation

  // OHTTP key ID
  const uint8_t test_key_id = 5;
  std::string broken_hex_private_key =
      "1a8cda5f5403a33e9041dd9bc82effd44960afaa764e6d03cfc4f8afce13477b";
  auto key_fetcher_manager =
      std::make_unique<server_common::FakeKeyFetcherManager>(
          absl::BytesToHexString(GetTestHpkePublicKey()),
          broken_hex_private_key, std::to_string(test_key_id));

  const std::string plaintext_payload = kPlaintextPayload;
  const auto decrypted_result =
      EncryptAndDecrypt(std::move(key_fetcher_manager), plaintext_payload);
  EXPECT_TRUE(absl::IsInvalidArgument(decrypted_result.status()));
}

TEST_F(EncryptionTest, DecryptEncapsulatedRequestSuccess) {
  KmsInstance kms;
  kms.CreateKeyPair();

  auto key_fetcher_manager = CreateKeyFetcherManager(CreatePublicKeyFetcher());
  const std::string plaintext_payload = kPlaintextPayload;
  const auto decrypted_result =
      EncryptAndDecrypt(std::move(key_fetcher_manager), plaintext_payload);
  EXPECT_EQ(decrypted_result->GetPlaintextData(), plaintext_payload);
}

TEST_F(EncryptionTest, DecryptEncapsulatedRequestMultipleKeyPairsInKmsSuccess) {
  KmsInstance kms;
  kms.CreateKeyPair();
  kms.CreateKeyPair();  // Create another key pair

  auto key_fetcher_manager = CreateKeyFetcherManager(CreatePublicKeyFetcher());
  const std::string plaintext_payload = kPlaintextPayload;
  const auto decrypted_result =
      EncryptAndDecrypt(std::move(key_fetcher_manager), plaintext_payload);
  EXPECT_EQ(decrypted_result->GetPlaintextData(), plaintext_payload);
}

TEST_F(EncryptionTest, DecryptEncapsulatedRequestAfterKeyRefreshSuccess) {
  // In this test case, we set key_refresh_flow_run_frequency_seconds
  // extremely
  // low to test the scenario where the local key cache in KeyFetcherManager
  // class object is refreshed before keys are used.

  KmsInstance kms;
  kms.CreateKeyPair();

  constexpr unsigned int key_refresh_flow_run_frequency_seconds = 10;
  constexpr unsigned int margin_seconds = 5;
  auto key_fetcher_manager = CreateKeyFetcherManager(
      CreatePublicKeyFetcher(), kDefaultPrivateKeyCacheTtlSeconds,
      key_refresh_flow_run_frequency_seconds);

  // Wait until the private key cache expires
  std::this_thread::sleep_for(std::chrono::seconds(
      key_refresh_flow_run_frequency_seconds + margin_seconds));

  // There is no straight forward way to check the key cache is actually
  // refreshed as a part of this test. We just assume the keys are refreshed
  // by
  // KeyFetcherManager::RunPeriodicKeyRefresh() while the above sleep.

  const std::string plaintext_payload = kPlaintextPayload;
  const auto decrypted_result =
      EncryptAndDecrypt(std::move(key_fetcher_manager), plaintext_payload);
  EXPECT_EQ(decrypted_result->GetPlaintextData(), plaintext_payload);
}

}  // namespace
}  // namespace privacy_sandbox::azure_encryption

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
