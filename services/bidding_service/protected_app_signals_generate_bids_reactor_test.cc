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

#include "services/bidding_service/protected_app_signals_generate_bids_reactor.h"

#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/synchronization/notification.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/grpcpp/server_context.h"
#include "services/bidding_service/base_generate_bids_reactor.h"
#include "services/bidding_service/constants.h"
#include "services/bidding_service/generate_bids_reactor_test_utils.h"
#include "services/common/clients/http_kv_server/buyer/ads_retrieval_async_http_client.h"
#include "services/common/constants/common_service_flags.h"
#include "services/common/encryption/key_fetcher_factory.h"
#include "services/common/encryption/mock_crypto_client_wrapper.h"
#include "services/common/metric/server_definition.h"
#include "services/common/test/mocks.h"
#include "services/common/test/random.h"
#include "services/common/util/json_util.h"
#include "src/cpp/encryption/key_fetcher/interface/key_fetcher_manager_interface.h"

namespace privacy_sandbox::bidding_auction_servers {
namespace {

using Request = GenerateProtectedAppSignalsBidsRequest;
using RawRequest = GenerateProtectedAppSignalsBidsRequest::
    GenerateProtectedAppSignalsBidsRawRequest;
using Response = GenerateProtectedAppSignalsBidsResponse;
using RawResponse = GenerateProtectedAppSignalsBidsResponse::
    GenerateProtectedAppSignalsBidsRawResponse;
using AdsRetrievalAsyncClientType =
    AsyncClientMock<AdRetrievalInput, AdRetrievalOutput>;

class GenerateBidsReactorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    TrustedServersConfigClient config_client({});
    config_client.SetFlagForTest(kTrue, ENABLE_ENCRYPTION);
    config_client.SetFlagForTest(kTrue, TEST_MODE);
    config_client.SetFlagForTest(kTrue, ENABLE_PROTECTED_APP_SIGNALS);
    log::PS_VLOG_IS_ON(/*verbose_level=*/0, /*max_v=*/20);

    key_fetcher_manager_ =
        CreateKeyFetcherManager(config_client, /*public_key_fetcher=*/nullptr);
    SetupMockCryptoClientWrapper(crypto_client_);
  }

  RawResponse RunReactorWithRequest(const RawRequest& raw_request,
                                    std::optional<BiddingServiceRuntimeConfig>
                                        runtime_config = std::nullopt) {
    if (!runtime_config.has_value()) {
      runtime_config = {
          .encryption_enabled = true,
          .enable_buyer_debug_url_generation = false,
          .enable_adtech_code_logging = false,
      };
    }
    // Create a request.
    auto request = CreateProtectedAppSignalsRequest(raw_request);

    // Run the request through the reactor and return the response.
    Response response;
    ProtectedAppSignalsGenerateBidsReactor reactor(
        &context_, dispatcher_, *runtime_config, &request, &response,
        key_fetcher_manager_.get(), &crypto_client_, &ad_retrieval_client_);
    reactor.Execute();
    RawResponse raw_response;
    raw_response.ParseFromString(response.response_ciphertext());
    return raw_response;
  }

  grpc::CallbackServerContext context_;
  MockCryptoClientWrapper crypto_client_;
  MockCodeDispatchClient dispatcher_;
  AdsRetrievalAsyncClientType ad_retrieval_client_;
  std::unique_ptr<server_common::KeyFetcherManagerInterface>
      key_fetcher_manager_;
};

TEST_F(GenerateBidsReactorTest, WinningBidIsGenerated) {
  int num_roma_dispatches = 0;
  SetupProtectedAppSignalsRomaExpectations(dispatcher_, num_roma_dispatches);

  EXPECT_CALL(ad_retrieval_client_, Execute)
      .WillOnce(
          [](std::unique_ptr<AdRetrievalInput> keys,
             const RequestMetadata& metadata,
             absl::AnyInvocable<
                 void(absl::StatusOr<std::unique_ptr<AdRetrievalOutput>>) &&>
                 on_done,
             absl::Duration timeout) {
            auto response = CreateAdsRetrievalResponse();
            EXPECT_TRUE(response.ok()) << response.status();
            std::move(on_done)(
                std::make_unique<AdRetrievalOutput>(*std::move(response)));
            return absl::OkStatus();
          });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  auto raw_response = RunReactorWithRequest(raw_request);

  // One dispatch to `preparedDataForAdRetrieval` and another to `generateBids`
  // is expected.
  ASSERT_EQ(num_roma_dispatches, 2);

  // Verify the bid returned by the generateBid UDF is the same returned by
  // the reactor.
  ASSERT_EQ(raw_response.bids().size(), 1);
  const auto& generated_bid = raw_response.bids()[0];
  EXPECT_EQ(generated_bid.bid(), kTestWinningBid);
  EXPECT_EQ(generated_bid.render(), kTestRenderUrl);
}

TEST_F(GenerateBidsReactorTest, AdsRetrievalTimeoutIsUsed) {
  int num_roma_dispatches = 0;
  SetupProtectedAppSignalsRomaExpectations(dispatcher_, num_roma_dispatches);

  EXPECT_CALL(ad_retrieval_client_, Execute)
      .WillOnce(
          [](std::unique_ptr<AdRetrievalInput> keys,
             const RequestMetadata& metadata,
             absl::AnyInvocable<
                 void(absl::StatusOr<std::unique_ptr<AdRetrievalOutput>>) &&>
                 on_done,
             absl::Duration timeout) {
            EXPECT_EQ(timeout, absl::Milliseconds(kTestAdRetrievalTimeoutMs));
            return absl::OkStatus();
          });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  RunReactorWithRequest(
      raw_request, BiddingServiceRuntimeConfig({
                       .encryption_enabled = true,
                       .enable_buyer_debug_url_generation = false,
                       .enable_adtech_code_logging = false,
                       .ad_retrieval_timeout_ms = kTestAdRetrievalTimeoutMs,
                   }));
}

TEST_F(GenerateBidsReactorTest, PrepareDataForAdRetrievalInputIsCorrect) {
  int num_roma_dispatches = 0;
  EXPECT_CALL(dispatcher_, BatchExecute)
      .WillRepeatedly([&num_roma_dispatches](
                          std::vector<DispatchRequest>& batch,
                          BatchDispatchDoneCallback batch_callback) {
        ++num_roma_dispatches;

        // First dispatch happens for `prepareDataForAdRetrieval` UDF.
        if (num_roma_dispatches == 1) {
          EXPECT_EQ(batch.size(), 1);
          const auto& inputs = batch[0].input;
          EXPECT_EQ(inputs.size(), kNumPrepareDataForRetrievalUdfArgs);
          EXPECT_EQ(
              *inputs[ArgIndex(
                  PrepareDataForRetrievalUdfArgs::kProtectedAppSignals)],
              absl::StrCat("\"", absl::BytesToHexString(kTestAppInstallSignals),
                           "\""));
          EXPECT_EQ(
              *inputs[ArgIndex(
                  PrepareDataForRetrievalUdfArgs::kProtectedAppSignalsVersion)],
              absl::StrCat(kTestEncodingVersion));
          EXPECT_EQ(*inputs[ArgIndex(
                        PrepareDataForRetrievalUdfArgs::kAuctionSignals)],
                    kTestAuctionSignals);
          EXPECT_EQ(
              *inputs[ArgIndex(PrepareDataForRetrievalUdfArgs::kBuyerSignals)],
              kTestBuyerSignals);

          return MockRomaExecution(batch, std::move(batch_callback),
                                   kPrepareDataForAdRetrievalEntryFunctionName,
                                   kPrepareDataForAdRetrievalBlobVersion,
                                   CreatePrepareDataForAdsRetrievalResponse());
        }
      });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  RunReactorWithRequest(raw_request);
}

TEST_F(GenerateBidsReactorTest, AdRetrievalClientInputIsCorrect) {
  int num_roma_dispatches = 0;
  SetupProtectedAppSignalsRomaExpectations(dispatcher_, num_roma_dispatches);

  EXPECT_CALL(ad_retrieval_client_, Execute)
      .WillOnce(
          [](std::unique_ptr<AdRetrievalInput> keys,
             const RequestMetadata& metadata,
             absl::AnyInvocable<
                 void(absl::StatusOr<std::unique_ptr<AdRetrievalOutput>>) &&>
                 on_done,
             absl::Duration timeout) {
            auto parsed_retrieval_data = ParseJsonString(keys->retrieval_data);
            auto decoded_signals_itr =
                parsed_retrieval_data->FindMember(kDecodedSignals);
            EXPECT_NE(decoded_signals_itr, parsed_retrieval_data->MemberEnd());
            EXPECT_EQ(std::string(decoded_signals_itr->value.GetString()),
                      kTestDecodedAppInstallSignals);

            auto retrieval_data_itr =
                parsed_retrieval_data->FindMember(kRetrievalData);
            EXPECT_NE(retrieval_data_itr, parsed_retrieval_data->MemberEnd());
            EXPECT_EQ(std::string(retrieval_data_itr->value.GetString()),
                      kTestRetrievalData);

            EXPECT_EQ(keys->contextual_signals, kTestBuyerSignals);

            auto response = CreateAdsRetrievalResponse();
            EXPECT_TRUE(response.ok()) << response.status();
            std::move(on_done)(
                std::make_unique<AdRetrievalOutput>(*std::move(response)));
            return absl::OkStatus();
          });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  auto raw_response = RunReactorWithRequest(raw_request);

  // One dispatch to `preparedDataForAdRetrieval` and another to `generateBids`
  // is expected.
  ASSERT_EQ(num_roma_dispatches, 2);

  // Verify the bid returned by the generateBid UDF is the same returned by
  // the reactor.
  ASSERT_EQ(raw_response.bids().size(), 1);
  const auto& generated_bid = raw_response.bids()[0];
  EXPECT_EQ(generated_bid.bid(), kTestWinningBid);
  EXPECT_EQ(generated_bid.render(), kTestRenderUrl);
}

TEST_F(GenerateBidsReactorTest, GenerateBidsInputIsCorrect) {
  int num_roma_dispatches = 0;
  EXPECT_CALL(dispatcher_, BatchExecute)
      .WillRepeatedly([&num_roma_dispatches](
                          std::vector<DispatchRequest>& batch,
                          BatchDispatchDoneCallback batch_callback) {
        ++num_roma_dispatches;

        if (num_roma_dispatches == 1) {
          // First dispatch happens for `prepareDataForAdRetrieval` UDF.
          return MockRomaExecution(batch, std::move(batch_callback),
                                   kPrepareDataForAdRetrievalEntryFunctionName,
                                   kPrepareDataForAdRetrievalBlobVersion,
                                   CreatePrepareDataForAdsRetrievalResponse());
        } else {
          // Second dispatch happens for `generateBid` UDF.
          EXPECT_EQ(batch.size(), 1);
          const auto& inputs = batch[0].input;
          EXPECT_EQ(inputs.size(), kNumGenerateBidsUdfArgs);

          // Verify ads match our expectations.
          EXPECT_EQ(*inputs[ArgIndex(GenerateBidsUdfArgs::kAds)],
                    kTestAdsRetrievalAdsResponse);

          EXPECT_EQ(*inputs[ArgIndex(GenerateBidsUdfArgs::kAuctionSignals)],
                    kTestAuctionSignals);
          EXPECT_EQ(*inputs[ArgIndex(GenerateBidsUdfArgs::kBuyerSignals)],
                    kTestBuyerSignals);

          // Verify Contextual Embeddings match our expectations.
          EXPECT_EQ(*inputs[ArgIndex(GenerateBidsUdfArgs::kAds)],
                    kTestAdsRetrievalAdsResponse);
          return MockRomaExecution(batch, std::move(batch_callback),
                                   kGenerateBidEntryFunction,
                                   kProtectedAppSignalsGenerateBidBlobVersion,
                                   CreateGenerateBidsUdfResponse());
        }
      });

  EXPECT_CALL(ad_retrieval_client_, Execute)
      .WillOnce(
          [](std::unique_ptr<AdRetrievalInput> keys,
             const RequestMetadata& metadata,
             absl::AnyInvocable<
                 void(absl::StatusOr<std::unique_ptr<AdRetrievalOutput>>) &&>
                 on_done,
             absl::Duration timeout) {
            auto response = CreateAdsRetrievalResponse();
            EXPECT_TRUE(response.ok()) << response.status();
            std::move(on_done)(
                std::make_unique<AdRetrievalOutput>(*std::move(response)));
            return absl::OkStatus();
          });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  RunReactorWithRequest(raw_request);

  // One dispatch to `preparedDataForAdRetrieval` and another to `generateBids`
  // is expected.
  ASSERT_EQ(num_roma_dispatches, 2);
}

TEST_F(GenerateBidsReactorTest, EgressFeaturesAreNotPopulated) {
  int num_roma_dispatches = 0;
  SetupProtectedAppSignalsRomaExpectations(dispatcher_, num_roma_dispatches);

  EXPECT_CALL(ad_retrieval_client_, Execute)
      .WillOnce(
          [](std::unique_ptr<AdRetrievalInput> keys,
             const RequestMetadata& metadata,
             absl::AnyInvocable<
                 void(absl::StatusOr<std::unique_ptr<AdRetrievalOutput>>) &&>
                 on_done,
             absl::Duration timeout) {
            auto response = CreateAdsRetrievalResponse();
            EXPECT_TRUE(response.ok()) << response.status();
            std::move(on_done)(
                std::make_unique<AdRetrievalOutput>(*std::move(response)));
            return absl::OkStatus();
          });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  auto raw_response = RunReactorWithRequest(raw_request);

  // One dispatch to `preparedDataForAdRetrieval` and another to `generateBids`
  // is expected.
  ASSERT_EQ(num_roma_dispatches, 2);

  ASSERT_EQ(raw_response.bids().size(), 1);
  const auto& generated_bid = raw_response.bids()[0];
  EXPECT_EQ(generated_bid.bid(), kTestWinningBid);
  EXPECT_EQ(generated_bid.render(), kTestRenderUrl);

  ASSERT_EQ(generated_bid.egress_features().size(), 0);
}

TEST_F(GenerateBidsReactorTest, ZeroBidsAreFiltered) {
  int num_roma_dispatches = 0;
  EXPECT_CALL(dispatcher_, BatchExecute)
      .WillRepeatedly([&num_roma_dispatches](
                          std::vector<DispatchRequest>& batch,
                          BatchDispatchDoneCallback batch_callback) {
        ++num_roma_dispatches;

        if (num_roma_dispatches == 1) {
          // First dispatch happens for `prepareDataForAdRetrieval` UDF.
          return MockRomaExecution(batch, std::move(batch_callback),
                                   kPrepareDataForAdRetrievalEntryFunctionName,
                                   kPrepareDataForAdRetrievalBlobVersion,
                                   CreatePrepareDataForAdsRetrievalResponse());
        } else {
          // Second dispatch happens for `generateBid` UDF.
          return MockRomaExecution(
              batch, std::move(batch_callback), kGenerateBidEntryFunction,
              kProtectedAppSignalsGenerateBidBlobVersion,
              CreateGenerateBidsUdfResponse(
                  kTestRenderUrl, /*bid=*/0.0,
                  /*egress_features_hex_string=*/"",
                  /*debug_reporting_urls=*/"RJSON({})JSON"));
        }
      });

  EXPECT_CALL(ad_retrieval_client_, Execute)
      .WillOnce(
          [](std::unique_ptr<AdRetrievalInput> keys,
             const RequestMetadata& metadata,
             absl::AnyInvocable<
                 void(absl::StatusOr<std::unique_ptr<AdRetrievalOutput>>) &&>
                 on_done,
             absl::Duration timeout) {
            auto response = CreateAdsRetrievalResponse();
            EXPECT_TRUE(response.ok()) << response.status();
            std::move(on_done)(
                std::make_unique<AdRetrievalOutput>(*std::move(response)));
            return absl::OkStatus();
          });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  auto raw_response = RunReactorWithRequest(raw_request);

  // One dispatch to `preparedDataForAdRetrieval` and another to `generateBids`
  // is expected.
  ASSERT_EQ(num_roma_dispatches, 2);

  ASSERT_EQ(raw_response.bids().size(), 0);
}

TEST_F(GenerateBidsReactorTest,
       EmptyAdRetrievalResponseMeansNoGenerateBidAttempt) {
  int num_roma_dispatches = 0;
  EXPECT_CALL(dispatcher_, BatchExecute)
      .WillRepeatedly([&num_roma_dispatches](
                          std::vector<DispatchRequest>& batch,
                          BatchDispatchDoneCallback batch_callback) {
        ++num_roma_dispatches;

        if (num_roma_dispatches == 1) {
          // First dispatch happens for `prepareDataForAdRetrieval` UDF.
          return MockRomaExecution(batch, std::move(batch_callback),
                                   kPrepareDataForAdRetrievalEntryFunctionName,
                                   kPrepareDataForAdRetrievalBlobVersion,
                                   CreatePrepareDataForAdsRetrievalResponse());
        }
      });

  EXPECT_CALL(ad_retrieval_client_, Execute)
      .WillOnce(
          [](std::unique_ptr<AdRetrievalInput> keys,
             const RequestMetadata& metadata,
             absl::AnyInvocable<
                 void(absl::StatusOr<std::unique_ptr<AdRetrievalOutput>>) &&>
                 on_done,
             absl::Duration timeout) {
            auto response = CreateAdsRetrievalResponse("");
            EXPECT_TRUE(response.ok()) << response.status();
            std::move(on_done)(
                std::make_unique<AdRetrievalOutput>(*std::move(response)));
            return absl::OkStatus();
          });

  auto raw_request = CreateRawProtectedAppSignalsRequest(
      kTestAuctionSignals, kTestBuyerSignals,
      CreateProtectedAppSignals(kTestAppInstallSignals, kTestEncodingVersion),
      kSeller, kPublisherName);
  RunReactorWithRequest(raw_request);

  // One dispatch to `preparedDataForAdRetrieval` and no dispatch to
  // `generateBids` is expected.
  ASSERT_EQ(num_roma_dispatches, 1);
}

}  // namespace
}  // namespace privacy_sandbox::bidding_auction_servers
