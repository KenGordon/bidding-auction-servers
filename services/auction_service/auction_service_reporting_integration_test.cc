//  Copyright 2024 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#include <thread>

#include "absl/random/random.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/blocking_counter.h"
#include "gtest/gtest.h"
#include "services/auction_service/auction_constants.h"
#include "services/auction_service/auction_service.h"
#include "services/auction_service/auction_service_integration_test_util.h"
#include "services/auction_service/code_wrapper/buyer_reporting_test_constants.h"
#include "services/auction_service/code_wrapper/seller_code_wrapper.h"
#include "services/auction_service/code_wrapper/seller_udf_wrapper_test_constants.h"
#include "services/common/clients/code_dispatcher/code_dispatch_client.h"
#include "services/common/clients/config/trusted_server_config_client.h"
#include "services/common/constants/common_service_flags.h"
#include "services/common/encryption/key_fetcher_factory.h"
#include "services/common/encryption/mock_crypto_client_wrapper.h"
#include "services/common/metric/server_definition.h"
#include "services/common/test/mocks.h"
#include "services/common/test/random.h"
#include "services/common/test/utils/test_init.h"
#include "services/common/util/request_response_constants.h"

namespace privacy_sandbox::bidding_auction_servers {
namespace {
constexpr absl::string_view kExpectedReportResultUrl =
    "http://"
    "test.com&bid=1&bidCurrency=EUR&highestScoringOtherBid=0&"
    "highestScoringOtherBidCurrency=???&topWindowHostname=fenceStreetJournal."
    "com&interestGroupOwner=barStandardAds.com";
<<<<<<< HEAD
constexpr char kTestIgOwner[] = "barStandardAds.com";
=======
constexpr absl::string_view kExpectedReportWinUrl =
    "http://test.com?seller=http://"
    "seller.com&interestGroupName=undefined&buyerReportingId=buyerReportingId&"
    "adCost=2&highestScoringOtherBid=0&madeHighestScoringOtherBid=false&"
    "signalsForWinner={\"testSignal\":\"testValue\"}&perBuyerSignals=1,test,2&"
    "auctionSignals=3,test,4&desirability=undefined&topLevelSeller=undefined&"
    "modifiedBid=undefined";
constexpr absl::string_view kExpectedReportWinUrlWithNullSignalsForWinner =
    "http://test.com?seller=http://"
    "seller.com&interestGroupName=undefined&buyerReportingId=buyerReportingId&"
    "adCost=2&highestScoringOtherBid=0&madeHighestScoringOtherBid=false&"
    "signalsForWinner=null&perBuyerSignals=1,test,2&auctionSignals=3,test,4&"
    "desirability=undefined&topLevelSeller=undefined&modifiedBid=undefined";

constexpr absl::string_view kTestTopLevelReportResultUrl =
    "http://"
    "test.com&bid=1&bidCurrency=undefined&highestScoringOtherBid=undefined&"
    "highestScoringOtherBidCurrency=undefined&topWindowHostname="
    "fenceStreetJournal.com&interestGroupOwner=barStandardAds.com";
constexpr absl::string_view kTestInteractionReportingUrl = "http://click.com";

>>>>>>> upstream-v3.11.0
class AuctionServiceReportingIntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    CommonTestInit();
    server_common::telemetry::TelemetryConfig config_proto;
    config_proto.set_mode(server_common::telemetry::TelemetryConfig::OFF);
    metric::MetricContextMap<ScoreAdsRequest>(
        server_common::telemetry::BuildDependentConfig(config_proto));
  }
};

TEST_F(AuctionServiceReportingIntegrationTest,
<<<<<<< HEAD
       ScoresAdsReturnsReportResultUrlsWithSellerAndBuyerCodeIsolation) {
=======
       ReportingForComponentAuctionSuccessWithSellerAndBuyerCodeIsolation) {
  ScoreAdsResponse response;
  AuctionServiceRuntimeConfig runtime_config = {
      .enable_report_result_url_generation = true,
      .enable_report_win_url_generation = true,
      .enable_seller_and_buyer_udf_isolation = true};
  TestBuyerReportingSignals test_buyer_reporting_signals;
  TestScoreAdsRequestConfig test_score_ads_request_config = {
      .test_buyer_reporting_signals = test_buyer_reporting_signals,
      .top_level_seller = kTopLevelSeller,
      .buyer_reporting_id = kBuyerReportingId,
      .interest_group_owner = kTestIgOwner};
  LoadAndRunScoreAdsForPA(runtime_config, test_score_ads_request_config,
                          kTestReportWinUdfWithValidation,
                          kSellerBaseCodeForComponentAuction, response);
  ScoreAdsResponse::ScoreAdsRawResponse raw_response;
  ASSERT_TRUE(raw_response.ParseFromString(response.response_ciphertext()));
  const auto& score_ad = raw_response.ad_score();
  const auto& component_seller_reporting_urls =
      score_ad.win_reporting_urls().component_seller_reporting_urls();
  const auto& component_buyer_reporting_urls =
      score_ad.win_reporting_urls().buyer_reporting_urls();
  EXPECT_GT(score_ad.desirability(), 0);
  EXPECT_EQ(component_seller_reporting_urls.reporting_url(),
            kExpectedComponentReportResultUrl);
  EXPECT_EQ(component_seller_reporting_urls.interaction_reporting_urls().size(),
            1);
  EXPECT_EQ(component_seller_reporting_urls.interaction_reporting_urls().at(
                kTestInteractionEvent),
            kTestInteractionReportingUrl);
  EXPECT_EQ(component_buyer_reporting_urls.reporting_url(),
            kExpectedComponentReportWinUrl);
  EXPECT_EQ(component_buyer_reporting_urls.interaction_reporting_urls().size(),
            1);
  EXPECT_EQ(component_buyer_reporting_urls.interaction_reporting_urls().at(
                kTestInteractionEvent),
            kTestInteractionReportingUrl);
}

TEST_F(AuctionServiceReportingIntegrationTest,
       ReportingForTopLevelAuctionSuccessWithSellerAndBuyerCodeIsolation) {
>>>>>>> upstream-v3.11.0
  ScoreAdsResponse response;
  AuctionServiceRuntimeConfig runtime_config = {
      .enable_report_result_url_generation = true,
      .enable_report_win_url_generation = true,
      .enable_seller_and_buyer_udf_isolation = true};
  TestBuyerReportingSignals test_buyer_reporting_signals;
  TestComponentAuctionResultData component_data =
      GenerateTestComponentAuctionResultData();
  component_data.test_component_seller = kTestSeller;
  TestScoreAdsRequestConfig test_score_ads_request_config = {
      .test_buyer_reporting_signals = test_buyer_reporting_signals,
      .buyer_reporting_id = kBuyerReportingId,
<<<<<<< HEAD
      .interest_group_owner = kTestIgOwner};
=======
      .interest_group_owner = kTestIgOwner,
      .component_auction_data = component_data};
>>>>>>> upstream-v3.11.0
  LoadAndRunScoreAdsForPA(runtime_config, test_score_ads_request_config,
                          kTestReportWinUdfWithValidation,
                          kSellerBaseCodeForComponentAuction, response);
  ScoreAdsResponse::ScoreAdsRawResponse raw_response;
  ASSERT_TRUE(raw_response.ParseFromString(response.response_ciphertext()));
  const auto& score_ad = raw_response.ad_score();
  const auto& top_level_seller_reporting_urls =
      score_ad.win_reporting_urls().top_level_seller_reporting_urls();
  const auto& component_seller_reporting_urls =
      score_ad.win_reporting_urls().component_seller_reporting_urls();
  const auto& component_buyer_reporting_urls =
      score_ad.win_reporting_urls().buyer_reporting_urls();
  EXPECT_GT(score_ad.desirability(), 0);
  EXPECT_EQ(top_level_seller_reporting_urls.reporting_url(),
            kTestTopLevelReportResultUrl);
  EXPECT_EQ(top_level_seller_reporting_urls.interaction_reporting_urls().at(
                kTestInteractionEvent),
            kTestInteractionReportingUrl);
  EXPECT_EQ(component_seller_reporting_urls.reporting_url(),
            component_data.test_component_report_result_url);
  EXPECT_EQ(component_seller_reporting_urls.interaction_reporting_urls().at(
                component_data.test_component_event),
            component_data.test_component_interaction_reporting_url);

  EXPECT_EQ(component_buyer_reporting_urls.reporting_url(),
            component_data.test_component_win_reporting_url);
  EXPECT_EQ(component_buyer_reporting_urls.interaction_reporting_urls().at(
                component_data.test_component_event),
            component_data.test_component_interaction_reporting_url);
}

TEST_F(AuctionServiceReportingIntegrationTest,
       ScoresAdsReturnsReportResultUrlsWithSellerAndBuyerCodeIsolation) {
  ScoreAdsResponse response;
  AuctionServiceRuntimeConfig runtime_config = {
      .enable_report_result_url_generation = true,
      .enable_report_win_url_generation = true,
      .enable_seller_and_buyer_udf_isolation = true};
  TestBuyerReportingSignals test_buyer_reporting_signals;
  TestScoreAdsRequestConfig test_score_ads_request_config = {
      .test_buyer_reporting_signals = test_buyer_reporting_signals,
      .buyer_reporting_id = kBuyerReportingId,
      .interest_group_owner = kTestIgOwner};
  LoadAndRunScoreAdsForPA(runtime_config, test_score_ads_request_config,
                          kTestReportWinUdfWithValidation, kSellerBaseCode,
                          response);
  ScoreAdsResponse::ScoreAdsRawResponse raw_response;
  ASSERT_TRUE(raw_response.ParseFromString(response.response_ciphertext()));
<<<<<<< HEAD
  const auto& scoredAd = raw_response.ad_score();
  EXPECT_GT(scoredAd.desirability(), 0);
  EXPECT_EQ(scoredAd.win_reporting_urls()
                .top_level_seller_reporting_urls()
                .reporting_url(),
            kExpectedReportResultUrl);
  EXPECT_EQ(scoredAd.win_reporting_urls()
=======
  const auto& score_ad = raw_response.ad_score();
  EXPECT_GT(score_ad.desirability(), 0);
  const auto& top_level_seller_reporting_urls =
      score_ad.win_reporting_urls().top_level_seller_reporting_urls();
  const auto& component_buyer_reporting_urls =
      score_ad.win_reporting_urls().buyer_reporting_urls();
  EXPECT_EQ(top_level_seller_reporting_urls.reporting_url(),
            kExpectedReportResultUrl);
  EXPECT_EQ(top_level_seller_reporting_urls.interaction_reporting_urls().size(),
            1);
  EXPECT_EQ(top_level_seller_reporting_urls.interaction_reporting_urls().at(
                kTestInteractionEvent),
            kTestInteractionReportingUrl);
  EXPECT_EQ(component_buyer_reporting_urls.reporting_url(),
            kExpectedReportWinUrl);
  EXPECT_EQ(component_buyer_reporting_urls.interaction_reporting_urls().size(),
            1);
  EXPECT_EQ(component_buyer_reporting_urls.interaction_reporting_urls().at(
                kTestInteractionEvent),
            kTestInteractionReportingUrl);
}

TEST_F(AuctionServiceReportingIntegrationTest,
       ScoresAdsSuccessWithPrivateAggregationEnabled) {
  ScoreAdsResponse response;
  AuctionServiceRuntimeConfig runtime_config = {
      .enable_report_result_url_generation = true,
      .enable_report_win_url_generation = true,
      .enable_seller_and_buyer_udf_isolation = true,
      .enable_private_aggregate_reporting = true};
  TestBuyerReportingSignals test_buyer_reporting_signals;
  TestScoreAdsRequestConfig test_score_ads_request_config = {
      .test_buyer_reporting_signals = test_buyer_reporting_signals,
      .buyer_reporting_id = kBuyerReportingId,
      .interest_group_owner = kTestIgOwner};
  LoadAndRunScoreAdsForPA(runtime_config, test_score_ads_request_config,
                          kTestReportWinUdfWithValidation,
                          kSellerBaseCodeWithPrivateAggregation, response);
  ScoreAdsResponse::ScoreAdsRawResponse raw_response;
  ASSERT_TRUE(raw_response.ParseFromString(response.response_ciphertext()));
  const auto& score_ad = raw_response.ad_score();
  EXPECT_GT(score_ad.desirability(), 0);
}

TEST_F(
    AuctionServiceReportingIntegrationTest,
    ReportingSuccessWithSellerAndBuyerCodeIsolationAndEmptySignalsForWinner) {
  ScoreAdsResponse response;
  AuctionServiceRuntimeConfig runtime_config = {
      .enable_report_result_url_generation = true,
      .enable_report_win_url_generation = true,
      .enable_seller_and_buyer_udf_isolation = true};
  TestBuyerReportingSignals test_buyer_reporting_signals;
  TestScoreAdsRequestConfig test_score_ads_request_config = {
      .test_buyer_reporting_signals = test_buyer_reporting_signals,
      .buyer_reporting_id = kBuyerReportingId,
      .interest_group_owner = kTestIgOwner};
  LoadAndRunScoreAdsForPA(runtime_config, test_score_ads_request_config,
                          kTestReportWinUdfWithValidation,
                          kSellerBaseCodeWithNoSignalsForWinner, response);
  ScoreAdsResponse::ScoreAdsRawResponse raw_response;
  ASSERT_TRUE(raw_response.ParseFromString(response.response_ciphertext()));
  const auto& score_ad = raw_response.ad_score();
  EXPECT_GT(score_ad.desirability(), 0);
  const auto& top_level_seller_reporting_urls =
      score_ad.win_reporting_urls().top_level_seller_reporting_urls();
  const auto& component_buyer_reporting_urls =
      score_ad.win_reporting_urls().buyer_reporting_urls();
  EXPECT_EQ(top_level_seller_reporting_urls.reporting_url(),
            kExpectedReportResultUrl);
  EXPECT_EQ(top_level_seller_reporting_urls.interaction_reporting_urls().size(),
            1);
  EXPECT_EQ(top_level_seller_reporting_urls.interaction_reporting_urls().at(
                kTestInteractionEvent),
            kTestInteractionReportingUrl);
  EXPECT_EQ(component_buyer_reporting_urls.reporting_url(),
            kExpectedReportWinUrlWithNullSignalsForWinner);
  EXPECT_EQ(component_buyer_reporting_urls.interaction_reporting_urls().size(),
            1);
  EXPECT_EQ(component_buyer_reporting_urls.interaction_reporting_urls().at(
                kTestInteractionEvent),
            kTestInteractionReportingUrl);
}

TEST_F(AuctionServiceReportingIntegrationTest,
       ReportResultSuccessWhenReportWinCodeNotLoaded) {
  ScoreAdsResponse response;
  AuctionServiceRuntimeConfig runtime_config = {
      .enable_report_result_url_generation = true,
      .enable_report_win_url_generation = true,
      .enable_seller_and_buyer_udf_isolation = true};
  TestBuyerReportingSignals test_buyer_reporting_signals;
  TestScoreAdsRequestConfig test_score_ads_request_config = {
      .test_buyer_reporting_signals = test_buyer_reporting_signals,
      .buyer_reporting_id = kBuyerReportingId,
      .interest_group_owner = kTestIgOwner};
  LoadAndRunScoreAdsForPA(runtime_config, test_score_ads_request_config, "",
                          kSellerBaseCodeWithNoSignalsForWinner, response);
  ScoreAdsResponse::ScoreAdsRawResponse raw_response;
  ASSERT_TRUE(raw_response.ParseFromString(response.response_ciphertext()));
  const auto& score_ad = raw_response.ad_score();
  EXPECT_GT(score_ad.desirability(), 0);
  EXPECT_EQ(score_ad.win_reporting_urls()
                .top_level_seller_reporting_urls()
                .reporting_url(),
            kExpectedReportResultUrl);
  EXPECT_EQ(score_ad.win_reporting_urls()
>>>>>>> upstream-v3.11.0
                .top_level_seller_reporting_urls()
                .interaction_reporting_urls()
                .size(),
            1);
<<<<<<< HEAD
  EXPECT_EQ(scoredAd.win_reporting_urls()
=======
  EXPECT_EQ(score_ad.win_reporting_urls()
>>>>>>> upstream-v3.11.0
                .top_level_seller_reporting_urls()
                .interaction_reporting_urls()
                .at(kTestInteractionEvent),
            kTestInteractionReportingUrl);
<<<<<<< HEAD
  EXPECT_TRUE(scoredAd.win_reporting_urls()
=======
  EXPECT_TRUE(score_ad.win_reporting_urls()
>>>>>>> upstream-v3.11.0
                  .buyer_reporting_urls()
                  .reporting_url()
                  .empty());
  EXPECT_EQ(score_ad.win_reporting_urls()
                .buyer_reporting_urls()
                .interaction_reporting_urls()
                .size(),
            0);
}

}  // namespace
}  // namespace privacy_sandbox::bidding_auction_servers
