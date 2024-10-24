//  Copyright 2022 Google LLC
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

#ifndef SERVICES_AUCTION_SERVICE_SCORE_ADS_REACTOR_H_
#define SERVICES_AUCTION_SERVICE_SCORE_ADS_REACTOR_H_

#include <limits>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>

#include <google/protobuf/text_format.h>
#include <rapidjson/stringbuffer.h>

#include "absl/status/statusor.h"
#include "api/bidding_auction_servers.pb.h"
#include "services/auction_service/benchmarking/score_ads_benchmarking_logger.h"
#include "services/auction_service/data/runtime_config.h"
#include "services/auction_service/reporting/reporting_helper.h"
#include "services/auction_service/reporting/reporting_response.h"
#include "services/common/clients/code_dispatcher/code_dispatch_client.h"
#include "services/common/code_dispatch/code_dispatch_reactor.h"
#include "services/common/encryption/crypto_client_wrapper_interface.h"
#include "services/common/loggers/request_context_impl.h"
#include "services/common/metric/server_definition.h"
#include "services/common/reporters/async_reporter.h"
#include "src/cpp/encryption/key_fetcher/interface/key_fetcher_manager_interface.h"

namespace privacy_sandbox::bidding_auction_servers {

inline constexpr char kDeviceComponentAuctionWithPAS[] =
    "Protected App Signals Auction Input cannot be considered for "
    "Device Component Auction";
inline constexpr char kNoAdsWithValidScoringSignals[] =
    "No ads with valid scoring signals.";
inline constexpr char kNoTrustedScoringSignals[] =
    "Empty trusted scoring signals";

// An aggregate of the data we track when scoring all the ads.
struct ScoringData {
  // Index of the most desirable ad. This helps us to set the overall response
  // object just once.
  int index_of_most_desirable_ad = 0;
  // Count of rejected bids.
  int seller_rejected_bid_count = 0;
  // Map of all the desirability/scores and corresponding scored ad's index in
  // the response from the scoreAd's UDF.
  absl::flat_hash_map<float, std::list<int>> score_ad_map;
  // Saving the desirability allows us to compare desirability between ads
  // without re-parsing the current most-desirable ad every time.
  float desirability_of_most_desirable_ad = 0;
  // List of rejection reasons provided by seller.
  std::vector<ScoreAdsResponse::AdScore::AdRejectionReason>
      ad_rejection_reasons;
  // The most desirable ad.
  std::optional<ScoreAdsResponse::AdScore> winning_ad;

  void UpdateWinner(int index, const ScoreAdsResponse::AdScore& ad_score);
};

// This is a gRPC reactor that serves a single ScoreAdsRequest.
// It stores state relevant to the request and after the
// response is finished being served, ScoreAdsReactor cleans up all
// necessary state and grpc releases the reactor from memory.
class ScoreAdsReactor
    : public CodeDispatchReactor<
          ScoreAdsRequest, ScoreAdsRequest::ScoreAdsRawRequest,
          ScoreAdsResponse, ScoreAdsResponse::ScoreAdsRawResponse> {
 public:
  explicit ScoreAdsReactor(
      CodeDispatchClient& dispatcher, const ScoreAdsRequest* request,
      ScoreAdsResponse* response,
      std::unique_ptr<ScoreAdsBenchmarkingLogger> benchmarking_logger,
      server_common::KeyFetcherManagerInterface* key_fetcher_manager,
      CryptoClientWrapperInterface* crypto_client,
      const AsyncReporter* async_reporter,
      const AuctionServiceRuntimeConfig& runtime_config);

  // Initiates the asynchronous execution of the ScoreAdsRequest.
  virtual void Execute();

 private:
  enum class AuctionScope : int { kSingleSeller, kDeviceComponentSeller };
  using AdWithBidMetadata =
      ScoreAdsRequest::ScoreAdsRawRequest::AdWithBidMetadata;
  using ProtectedAppSignalsAdWithBidMetadata =
      ScoreAdsRequest::ScoreAdsRawRequest::ProtectedAppSignalsAdWithBidMetadata;
  // Finds the ad type of the scored ad and set it. After the function call,
  // expect one of the input pointers to be populated.
  void FindScoredAdType(absl::string_view response_id,
                        AdWithBidMetadata** ad_with_bid_metadata,
                        ProtectedAppSignalsAdWithBidMetadata**
                            protected_app_signals_ad_with_bid_metadata);
  // Populates the ad render URL and other ad type specific data in the ad score
  // response to be sent back to SFE.
  void PopulateRelevantFieldsInResponse(int index_of_most_desirable_ad,
                                        absl::string_view request_id,
                                        ScoreAdsResponse::AdScore& winning_ad);
  // Finds the winning ad (if one exists) among the responses returned by Roma.
  // Returns all the data associated with scoring that can then be later used
  // for finding second highest bid (among other things).
  ScoringData FindWinningAd(
      const std::vector<absl::StatusOr<DispatchResponse>>& responses);
  // Populates the data about the highest second other bid in the response to
  // be returned to SFE.
  void PopulateHighestScoringOtherBidsData(
      int index_of_most_desirable_ad,
      const absl::flat_hash_map<float, std::list<int>>& score_ad_map,
      const std::vector<absl::StatusOr<DispatchResponse>>& responses,
      ScoreAdsResponse::AdScore& winning_ad);

  // Asynchronous callback used by the v8 code executor to return a result. This
  // will be called in a different thread owned by the code dispatch library.
  //
  // output: a status or DispatchResponse representing the result of the code
  // dispatch execution.
  // ad: the ad and bid that was scored.
  void ScoreAdsCallback(
      const std::vector<absl::StatusOr<DispatchResponse>>& output);

  absl::btree_map<std::string, std::string> GetLoggingContext(
      const ScoreAdsRequest::ScoreAdsRawRequest& score_ads_request);

  // Performs debug reporting for all scored ads by the seller.
  void PerformDebugReporting(
      const std::optional<ScoreAdsResponse::AdScore>& winning_ad_score);

  static constexpr char kRomaTimeoutMs[] = "TimeoutMs";

  template <typename T>
  void DispatchReportingRequest(
      const T& ad, const ScoreAdsResponse::AdScore& winning_ad_score,
      absl::string_view id, std::shared_ptr<std::string> auction_config,
      const std::string& handler_name,
      const BuyerReportingMetadata& buyer_metadata,
      std::optional<ComponentReportingMetadata> component_reporting_metadata,
      absl::string_view egress_features = "") {
    DispatchRequest dispatch_request = GetReportingDispatchRequest(
        winning_ad_score, raw_request_.publisher_hostname(),
        enable_adtech_code_logging_, auction_config, log_context_,
        buyer_metadata, component_reporting_metadata, handler_name,
        egress_features);
    dispatch_request.tags[kRomaTimeoutMs] = roma_timeout_ms_;

    std::vector<DispatchRequest> dispatch_requests = {dispatch_request};
    auto status = dispatcher_.BatchExecute(
        dispatch_requests,
        [this](const std::vector<absl::StatusOr<DispatchResponse>>& result) {
          ReportingCallback(result);
        });

    if (!status.ok()) {
      std::string original_request;
      google::protobuf::TextFormat::PrintToString(raw_request_,
                                                  &original_request);
      PS_VLOG(1, log_context_)
          << "Reporting execution request failed for batch: "
          << original_request
          << status.ToString(absl::StatusToStringMode::kWithEverything);
      EncryptAndFinishOK();
    }
  }
  void PerformReporting(const ScoreAdsResponse::AdScore& winning_ad_score,
                        absl::string_view id);

  // Publishes metrics and Finishes the RPC call with a status.
  void FinishWithStatus(const grpc::Status& status);

  // Encrypt response and Finishes the RPC call with an OK status.
  void EncryptAndFinishOK();

  void ReportingCallback(
      const std::vector<absl::StatusOr<DispatchResponse>>& responses);

  void MayPopulateProtectedAppSignalsDispatchRequests(
      bool enable_debug_reporting,
      const absl::flat_hash_map<std::string, rapidjson::StringBuffer>&
          scoring_signals,
      std::shared_ptr<std::string> auction_config,
      google::protobuf::RepeatedPtrField<ProtectedAppSignalsAdWithBidMetadata>&
          protected_app_signals_ad_bids);

  // Sets the required fields in the passed AdScore object and populates
  // scoring data.
  // The AdScore fields that need to be parsed from ROMA response
  // must be populated separately before this is called.
  void HandleScoredAd(int index, float bid,
                      absl::string_view interest_group_name,
                      absl::string_view interest_group_owner,
                      const rapidjson::Document& response_json, AdType ad_type,
                      ScoreAdsResponse::AdScore& score_ads_response,
                      ScoringData& scoring_data);

  // The key is the id of the DispatchRequest, and the value is the ad
  // used to create the dispatch request. This map is used to amend each ad's
  // DispatchResponse with more data which is then passed into the final
  // ScoreAdsResponse.
  absl::flat_hash_map<
      std::string,
      std::unique_ptr<ScoreAdsRequest::ScoreAdsRawRequest::AdWithBidMetadata>>
      ad_data_;
  absl::flat_hash_map<std::string,
                      std::unique_ptr<ProtectedAppSignalsAdWithBidMetadata>>
      protected_app_signals_ad_data_;
  std::unique_ptr<ScoreAdsBenchmarkingLogger> benchmarking_logger_;
  const AsyncReporter& async_reporter_;
  bool enable_seller_debug_url_generation_;
  std::string roma_timeout_ms_;
  log::ContextImpl log_context_;

  // Used to log metric, same life time as reactor.
  std::unique_ptr<metric::AuctionContext> metric_context_;

  std::vector<std::unique_ptr<ScoreAdsResponse::AdScore>> ad_scores_;

  // Flags needed to be passed as input to the code which wraps AdTech provided
  // code.
  bool enable_adtech_code_logging_;
  bool enable_report_result_url_generation_;
  bool enable_report_win_url_generation_;
  const bool enable_protected_app_signals_;
  bool enable_report_win_input_noising_;
  std::string seller_origin_;
  int max_allowed_size_debug_url_chars_;
  long max_allowed_size_all_debug_urls_chars_;

  // Specifies whether this is a single seller or component auction.
  // Impacts the creation of scoreAd input params and
  // parsing of scoreAd output.
  AuctionScope auction_scope_;
};
}  // namespace privacy_sandbox::bidding_auction_servers
#endif  // SERVICES_AUCTION_SERVICE_SCORE_ADS_REACTOR_H_
