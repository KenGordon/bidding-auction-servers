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

#include "score_ads_reactor.h"

#include <algorithm>
#include <limits>
#include <list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/util/json_util.h>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_replace.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/pointer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "services/auction_service/auction_constants.h"
#include "services/auction_service/code_wrapper/seller_code_wrapper.h"
#include "services/auction_service/reporting/reporting_response.h"
#include "services/common/util/json_util.h"
#include "services/common/util/reporting_util.h"
#include "services/common/util/request_response_constants.h"
#include "src/cpp/util/status_macro/status_macros.h"
#include "src/cpp/util/status_macro/status_util.h"

namespace privacy_sandbox::bidding_auction_servers {
namespace {

using ::google::protobuf::TextFormat;
using AdWithBidMetadata =
    ScoreAdsRequest::ScoreAdsRawRequest::AdWithBidMetadata;
using ProtectedAppSignalsAdWithBidMetadata =
    ScoreAdsRequest::ScoreAdsRawRequest::ProtectedAppSignalsAdWithBidMetadata;
using ::google::protobuf::RepeatedPtrField;
using HighestScoringOtherBidsMap =
    ::google::protobuf::Map<std::string, google::protobuf::ListValue>;

constexpr char DispatchHandlerFunctionWithSellerWrapper[] =
    "scoreAdEntryFunction";
constexpr char kAdComponentRenderUrlsProperty[] = "adComponentRenderUrls";
constexpr char kRenderUrlsPropertyForKVResponse[] = "renderUrls";
constexpr char kRenderUrlsPropertyForScoreAd[] = "renderUrl";
constexpr int kArgSizeWithWrapper = 7;

// The following fields are expected to returned by ScoreAd response
constexpr char kDesirabilityPropertyForScoreAd[] = "desirability";
constexpr char kAllowComponentAuctionPropertyForScoreAd[] =
    "allowComponentAuction";
constexpr char kAdMetadataForComponentAuction[] = "ad";
constexpr char kModifiedBidForComponentAuction[] = "bid";
constexpr char kRejectReasonPropertyForScoreAd[] = "rejectReason";
constexpr char kDebugReportUrlsPropertyForScoreAd[] = "debugReportUrls";
constexpr char kAuctionDebugLossUrlPropertyForScoreAd[] = "auctionDebugLossUrl";
constexpr char kAuctionDebugWinUrlPropertyForScoreAd[] = "auctionDebugWinUrl";
constexpr char kTopLevelSeller[] = "topLevelSeller";

constexpr int kBytesMultiplyer = 1024;

std::string MakeDeviceSignals(
    absl::string_view publisher_hostname,
    absl::string_view interest_group_owner, absl::string_view render_url,
    const google::protobuf::RepeatedPtrField<std::string>&
        ad_component_render_urls,
    absl::string_view top_level_seller) {
  std::string device_signals =
      absl::StrCat("{", R"("interestGroupOwner":")", interest_group_owner, "\"",
                   R"(,"topWindowHostname":")", publisher_hostname, "\"");

  if (!ad_component_render_urls.empty()) {
    absl::StrAppend(&device_signals, R"(,"adComponents":[)");
    for (int i = 0; i < ad_component_render_urls.size(); i++) {
      absl::StrAppend(&device_signals, "\"", ad_component_render_urls.at(i),
                      "\"");
      if (i != ad_component_render_urls.size() - 1) {
        absl::StrAppend(&device_signals, ",");
      }
    }
    absl::StrAppend(&device_signals, R"(])");
  }
  // Only add top level seller to device signals if it's non empty.
  if (!top_level_seller.empty()) {
    absl::StrAppend(&device_signals, R"JSON(,")JSON", kTopLevelSeller,
                    R"JSON(":")JSON", top_level_seller, R"JSON(")JSON");
  }
  absl::StrAppend(&device_signals, ",\"", kRenderUrlsPropertyForScoreAd,
                  "\":\"", render_url, "\"}");
  return device_signals;
}

constexpr int ScoreArgIndex(ScoreAdArgs arg) {
  return static_cast<std::underlying_type_t<ScoreAdArgs>>(arg);
}

void MayLogScoreAdsInput(const std::vector<std::shared_ptr<std::string>>& input,
                         log::ContextImpl& log_context) {
  PS_VLOG(2, log_context)
      << "\n\nScore Ad Input Args:"
      << "\nAdMetadata:\n"
      << *(input[ScoreArgIndex(ScoreAdArgs::kAdMetadata)]) << "\nBid:\n"
      << *(input[ScoreArgIndex(ScoreAdArgs::kBid)]) << "\nAuction Config:\n"
      << *(input[ScoreArgIndex(ScoreAdArgs::kAuctionConfig)])
      << "\nScoring Signals:\n"
      << *(input[ScoreArgIndex(ScoreAdArgs::kScoringSignals)])
      << "\nDevice Signals:\n"
      << *(input[ScoreArgIndex(ScoreAdArgs::kDeviceSignals)])
      << "\nDirectFromSellerSignals:\n"
      << (input[ScoreArgIndex(ScoreAdArgs::kDirectFromSellerSignals)]);
}

/**
 * Builds the ScoreAdInput, following the description here:
 * https://github.com/privacysandbox/fledge-docs/blob/main/bidding_auction_services_api.md#scoreads
 * and here
 * https://github.com/WICG/turtledove/blob/main/FLEDGE.md#23-scoring-bids.
 *
 * NOTE: All inputs MUST be valid JSON, not just something Javascript would
 * accept. Property names need to be in quotes! Additionally: See issues with
 * input formatting in b/258697130.
 */
template <typename T>
std::vector<std::shared_ptr<std::string>> ScoreAdInput(
    const T& ad, std::shared_ptr<std::string> auction_config,
    const absl::flat_hash_map<std::string, rapidjson::StringBuffer>&
        scoring_signals,
    log::ContextImpl& log_context, bool enable_adtech_code_logging,
    bool enable_debug_reporting, absl::string_view device_signals) {
  std::vector<std::shared_ptr<std::string>> input(
      kArgSizeWithWrapper);  // ScoreAdArgs size

  // TODO: b/260265272
  std::string adMetadataAsJson;
  const auto& it = ad.ad().struct_value().fields().find("metadata");
  if (it != ad.ad().struct_value().fields().end()) {
    google::protobuf::util::MessageToJsonString(it->second, &adMetadataAsJson);
  }
  input[ScoreArgIndex(ScoreAdArgs::kAdMetadata)] =
      std::make_shared<std::string>(adMetadataAsJson);
  input[ScoreArgIndex(ScoreAdArgs::kBid)] =
      std::make_shared<std::string>(std::to_string(ad.bid()));
  input[ScoreArgIndex(ScoreAdArgs::kAuctionConfig)] = auction_config;
  // TODO(b/258697130): Roma client string support bug
  input[ScoreArgIndex(ScoreAdArgs::kScoringSignals)] =
      std::make_shared<std::string>(
          scoring_signals.at(ad.render()).GetString());
  input[ScoreArgIndex(ScoreAdArgs::kDeviceSignals)] =
      std::make_shared<std::string>(device_signals);
  // This is only added to prevent errors in the score ad script, and
  // will always be an empty object.
  input[ScoreArgIndex(ScoreAdArgs::kDirectFromSellerSignals)] =
      std::make_shared<std::string>("{}");
  input[ScoreArgIndex(ScoreAdArgs::kFeatureFlags)] =
      std::make_shared<std::string>(GetFeatureFlagJson(
          enable_adtech_code_logging, enable_debug_reporting));

  MayLogScoreAdsInput(input, log_context);
  return input;
}

template <typename T>
DispatchRequest BuildScoreAdRequest(
    const T& ad, std::shared_ptr<std::string> auction_config,
    const absl::flat_hash_map<std::string, rapidjson::StringBuffer>&
        scoring_signals,
    const bool enable_debug_reporting, log::ContextImpl& log_context,
    const bool enable_adtech_code_logging, absl::string_view device_signals) {
  // Construct the wrapper struct for our V8 Dispatch Request.
  DispatchRequest score_ad_request;
  // TODO(b/250893468) Revisit dispatch id.
  score_ad_request.id = ad.render();
  // TODO(b/258790164) Update after code is fetched periodically.
  score_ad_request.version_string = "v1";
  score_ad_request.handler_name = DispatchHandlerFunctionWithSellerWrapper;

  score_ad_request.input = ScoreAdInput(ad, auction_config, scoring_signals,
                                        log_context, enable_adtech_code_logging,
                                        enable_debug_reporting, device_signals);
  return score_ad_request;
}

// Builds a map of render urls to JSON objects holding the scoring signals.
// An entry looks like: url_to_signals["fooAds.com/123"] = {"fooAds.com/123":
// {"some", "scoring", "signals"}}. Notice the render URL is present in the map
// both as its key, and again in each entry as a key to the JSON object. This is
// intentional, as it allows moving the key to the new signals objects being
// built for each AdWithBid.
absl::flat_hash_map<std::string, rapidjson::Document> BuildAdScoringSignalsMap(
    rapidjson::Value& trusted_scoring_signals_value) {
  absl::flat_hash_map<std::string, rapidjson::Document> url_to_signals;
  for (rapidjson::Value::MemberIterator itr =
           trusted_scoring_signals_value.MemberBegin();
       itr != trusted_scoring_signals_value.MemberEnd(); ++itr) {
    // Moving the name will render it inaccessible unless a copy is made first.
    std::string ad_url = itr->name.GetString();
    // A Document rather than a Value is created, as a Document has an
    // Allocator.
    rapidjson::Document ad_details;
    ad_details.SetObject();
    // AddMember moves itr's Values, do not reference them anymore.
    ad_details.AddMember(itr->name, itr->value, ad_details.GetAllocator());
    url_to_signals.try_emplace(std::move(ad_url), std::move(ad_details));
  }
  return url_to_signals;
}

// Builds a set of ad component render urls for components used in more than one
// ad with bid. Since a single ad component might be a part of multiple ads, and
// since rapidjson enforces moves over copies unless explicitly specified
// otherwise (that's what makes it "rapid"), we need to know which ad component
// scoring signals need to be copied rather than moved. Otherwise, for an ad
// component used n times, moving its signals would fail on all times except the
// first. O(n) operation, where n is the number of ad component render urls.
absl::flat_hash_set<std::string> FindSharedComponentUrls(
    const google::protobuf::RepeatedPtrField<AdWithBidMetadata>&
        ads_with_bids) {
  absl::flat_hash_map<std::string, int> url_occurrences;
  absl::flat_hash_set<std::string> multiple_occurrence_component_urls;
  for (const auto& ad_with_bid : ads_with_bids) {
    for (const auto& ad_component_render_url : ad_with_bid.ad_components()) {
      ++url_occurrences[ad_component_render_url];
      if (url_occurrences[ad_component_render_url] > 1) {
        std::string copy_of_ad_component_render_url = ad_component_render_url;
        multiple_occurrence_component_urls.emplace(
            std::move(copy_of_ad_component_render_url));
      }
    }
  }
  return multiple_occurrence_component_urls;
}

// Adds scoring signals for ad component render urls to signals object
// for a single ad with bid, `ad_with_bid`.
// `ad_with_bid` and `multiple_occurrence_component_urls` will only
// be read from. `component_signals` must be filled with the trusted scoring
// signals for this ad's ad component render urls. If an ad component render url
// is not in `multiple_occurrence_component_urls`, then its signals will be
// moved out from `component signals`. Else they will be copied for use here and
// left intact for use in future calls to this method.
// Returns a JSON document that contains the scoring signals for all ad
// component render URLs in this ad_with_bid.
absl::StatusOr<rapidjson::Document> AddComponentSignals(
    const AdWithBidMetadata& ad_with_bid,
    const absl::flat_hash_set<std::string>& multiple_occurrence_component_urls,
    absl::flat_hash_map<std::string, rapidjson::Document>& component_signals) {
  // Create overall signals object.
  rapidjson::Document combined_signals_for_this_bid;
  combined_signals_for_this_bid.SetObject();
  // Create empty expandable object to add ad component signals to.
  rapidjson::Document empty_object;
  empty_object.SetObject();
  // Add the expandable object to the combined signals object.
  auto combined_signals_itr =
      combined_signals_for_this_bid
          .AddMember(kAdComponentRenderUrlsProperty, empty_object,
                     combined_signals_for_this_bid.GetAllocator())
          .MemberBegin();

  for (const auto& ad_component_render_url : ad_with_bid.ad_components()) {
    // Check if there are signals for this component ad.
    auto component_url_signals_itr =
        component_signals.find(ad_component_render_url);
    if (component_url_signals_itr == component_signals.end()) {
      continue;
    }
    // Copy only if necessary.
    rapidjson::Document to_add;
    if (multiple_occurrence_component_urls.contains(ad_component_render_url)) {
      // Use the allocator of the object to which these signals are
      // ultimately going.
      to_add.CopyFrom(component_url_signals_itr->second,
                      combined_signals_for_this_bid.GetAllocator());
    } else {
      to_add.Swap(component_url_signals_itr->second);
    }
    // Grab member to avoid finding it twice.
    auto comp_url_signals_to_move_from =
        to_add.FindMember(ad_component_render_url.c_str());
    // This should never happen, the map entry's signals should always
    // be for the URL on which the map is keyed.
    if (comp_url_signals_to_move_from == to_add.MemberEnd()) {
      // This can only be caused by an error forming the map on our
      // side.
      return absl::Status(
          absl::StatusCode::kInternal,
          "Internal error while processing trusted scoring signals.");
    }
    // AddMember moves the values input into it, do not reference them
    // anymore.
    combined_signals_itr->value.AddMember(
        comp_url_signals_to_move_from->name,
        comp_url_signals_to_move_from->value,
        combined_signals_for_this_bid.GetAllocator());
  }
  return combined_signals_for_this_bid;
}

void MayPopulateScoringSignalsForProtectedAppSignals(
    const ScoreAdsRequest::ScoreAdsRawRequest& raw_request,
    absl::flat_hash_map<std::string, rapidjson::Document>& render_url_signals,
    absl::flat_hash_map<std::string, rapidjson::Document>& combined_signals,
    log::ContextImpl& log_context) {
  PS_VLOG(8, log_context) << __func__;
  for (const auto& protected_app_signals_ad_bid :
       raw_request.protected_app_signals_ad_bids()) {
    auto it = render_url_signals.find(protected_app_signals_ad_bid.render());
    if (it == render_url_signals.end()) {
      PS_VLOG(5, log_context)
          << "Skipping protected app signals ad since render "
             "URL is not found in the scoring signals: "
          << protected_app_signals_ad_bid.render();
      continue;
    }

    rapidjson::Document combined_signals_for_this_bid(rapidjson::kObjectType);
    combined_signals_for_this_bid.AddMember(
        kRenderUrlsPropertyForScoreAd, it->second,
        combined_signals_for_this_bid.GetAllocator());
    const auto& [unused_it, succeeded] =
        combined_signals.try_emplace(protected_app_signals_ad_bid.render(),
                                     std::move(combined_signals_for_this_bid));
    if (!succeeded) {
      PS_VLOG(1, log_context) << "Render URL overlaps between bids: "
                              << protected_app_signals_ad_bid.render();
    }
  }
}

absl::StatusOr<absl::flat_hash_map<std::string, rapidjson::StringBuffer>>
BuildTrustedScoringSignals(
    const ScoreAdsRequest::ScoreAdsRawRequest& raw_request,
    log::ContextImpl& log_context) {
  rapidjson::Document trusted_scoring_signals_value;
  // TODO (b/285214424): De-nest, use a guard.
  if (!raw_request.scoring_signals().empty()) {
    // Attempt to parse into an object.
    auto start_parse_time = absl::Now();
    rapidjson::ParseResult parse_result =
        trusted_scoring_signals_value.Parse<rapidjson::kParseFullPrecisionFlag>(
            raw_request.scoring_signals().data());
    if (parse_result.IsError()) {
      // TODO (b/285215004): Print offset to ease debugging.
      PS_VLOG(2, log_context)
          << "Trusted scoring signals JSON parse error: "
          << rapidjson::GetParseError_En(parse_result.Code())
          << ", trusted signals were: " << raw_request.scoring_signals();
      return absl::InvalidArgumentError("Malformed trusted scoring signals");
    }
    // Build a map of the signals for each render URL.
    auto render_urls_itr = trusted_scoring_signals_value.FindMember(
        kRenderUrlsPropertyForKVResponse);
    if (render_urls_itr == trusted_scoring_signals_value.MemberEnd()) {
      // If there are no scoring signals for any render urls, none can be
      // scored. Abort now.
      return absl::InvalidArgumentError(
          "Trusted scoring signals include no render urls.");
    }
    absl::flat_hash_map<std::string, rapidjson::Document> render_url_signals =
        BuildAdScoringSignalsMap(render_urls_itr->value);
    // No scoring signals for ad component render urls are required,
    // however if present we build a map to their scoring signals in the same
    // way.
    absl::flat_hash_map<std::string, rapidjson::Document> component_signals;
    auto component_urls_itr = trusted_scoring_signals_value.FindMember(
        kAdComponentRenderUrlsProperty);
    if (component_urls_itr != trusted_scoring_signals_value.MemberEnd()) {
      component_signals = BuildAdScoringSignalsMap(component_urls_itr->value);
    }

    // Find the ad component render urls used more than once so we know which
    // signals we must copy rather than move.
    absl::flat_hash_set<std::string> multiple_occurrence_component_urls =
        FindSharedComponentUrls(raw_request.ad_bids());
    // Each AdWithBid needs signals for both its render URL and its ad component
    // render urls.
    absl::flat_hash_map<std::string, rapidjson::Document> combined_signals;
    for (const auto& ad_with_bid : raw_request.ad_bids()) {
      // Now that we have a map of all component signals and all ad signals, we
      // can build the object.
      // Check for the render URL's signals; skip if none.
      // (Ad with bid will not be scored anyways in that case.)
      auto render_url_signals_itr =
          render_url_signals.find(ad_with_bid.render());
      if (render_url_signals_itr == render_url_signals.end()) {
        continue;
      }
      absl::StatusOr<rapidjson::Document> combined_signals_for_this_bid;
      PS_ASSIGN_OR_RETURN(
          combined_signals_for_this_bid,
          AddComponentSignals(ad_with_bid, multiple_occurrence_component_urls,
                              component_signals));
      // Do not reference values after move.
      combined_signals_for_this_bid->AddMember(
          kRenderUrlsPropertyForScoreAd, render_url_signals_itr->second,
          combined_signals_for_this_bid->GetAllocator());
      combined_signals.try_emplace(ad_with_bid.render(),
                                   *std::move(combined_signals_for_this_bid));
    }

    MayPopulateScoringSignalsForProtectedAppSignals(
        raw_request, render_url_signals, combined_signals, log_context);

    // Now turn the editable JSON documents into string buffers before
    // returning.
    absl::flat_hash_map<std::string, rapidjson::StringBuffer>
        combined_formatted_ad_signals;
    for (const auto& [render_url, scoring_signals_json_obj] :
         combined_signals) {
      rapidjson::StringBuffer buffer;
      rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
      scoring_signals_json_obj.Accept(writer);
      combined_formatted_ad_signals.try_emplace(render_url, std::move(buffer));
    }

    PS_VLOG(2, log_context)
        << "\nTrusted Scoring Signals Deserialize Time: "
        << ToInt64Microseconds((absl::Now() - start_parse_time))
        << " microseconds for " << combined_formatted_ad_signals.size()
        << " signals.";
    return combined_formatted_ad_signals;
  } else {
    return absl::InvalidArgumentError(kNoTrustedScoringSignals);
  }
}

std::shared_ptr<std::string> BuildAuctionConfig(
    const ScoreAdsRequest::ScoreAdsRawRequest& raw_request) {
  return std::make_shared<std::string>(absl::StrCat(
      "{\"auctionSignals\": ",
      ((raw_request.auction_signals().empty()) ? "\"\""
                                               : raw_request.auction_signals()),
      ", ", "\"sellerSignals\": ",
      ((raw_request.seller_signals().empty()) ? "\"\""
                                              : raw_request.seller_signals()),
      "}"));
}

absl::StatusOr<rapidjson::Document> ParseAndGetScoreAdResponseJson(
    bool enable_ad_tech_code_logging, const std::string& response,
    log::ContextImpl& log_context) {
  PS_ASSIGN_OR_RETURN(rapidjson::Document document, ParseJsonString(response));
  MayVlogAdTechCodeLogs(enable_ad_tech_code_logging, document, log_context);
  rapidjson::Document response_obj;
  auto iterator = document.FindMember("response");
  if (iterator != document.MemberEnd()) {
    if (iterator->value.IsObject()) {
      response_obj.CopyFrom(iterator->value, response_obj.GetAllocator());
    } else if (iterator->value.IsNumber()) {
      response_obj.SetDouble(iterator->value.GetDouble());
    }
  }
  return response_obj;
}

inline void MayVlogRomaResponses(
    const std::vector<absl::StatusOr<DispatchResponse>>& responses,
    log::ContextImpl& log_context) {
  if (log::PS_VLOG_IS_ON(2)) {
    for (const auto& dispatch_response : responses) {
      PS_VLOG(2, log_context)
          << "ScoreAds V8 Response: " << dispatch_response.status();
      if (dispatch_response.ok()) {
        PS_VLOG(2, log_context) << dispatch_response->resp;
      }
    }
  }
}

inline void LogWarningForBadResponse(
    const absl::Status& status, const DispatchResponse& response,
    const AdWithBidMetadata* ad_with_bid_metadata,
    log::ContextImpl& log_context) {
  PS_VLOG(0, log_context) << "Failed to parse response from Roma ",
      status.ToString(absl::StatusToStringMode::kWithEverything);
  if (ad_with_bid_metadata) {
    ABSL_LOG(WARNING)
        << "Invalid json output from code execution for interest group "
        << ad_with_bid_metadata->interest_group_name() << ": " << response.resp;
  } else {
    ABSL_LOG(WARNING)
        << "Invalid json output from code execution for protected app signals "
           "ad: "
        << response.resp;
  }
}

inline void UpdateHighestScoringOtherBidMap(
    float bid, absl::string_view owner,
    HighestScoringOtherBidsMap& highest_scoring_other_bids_map) {
  highest_scoring_other_bids_map.try_emplace(owner,
                                             google::protobuf::ListValue());
  highest_scoring_other_bids_map.at(owner).add_values()->set_number_value(bid);
}

}  // namespace

void ScoringData::UpdateWinner(int index,
                               const ScoreAdsResponse::AdScore& ad_score) {
  winning_ad = ad_score;
  index_of_most_desirable_ad = index;
  desirability_of_most_desirable_ad = ad_score.desirability();
}

ScoreAdsReactor::ScoreAdsReactor(
    CodeDispatchClient& dispatcher, const ScoreAdsRequest* request,
    ScoreAdsResponse* response,
    std::unique_ptr<ScoreAdsBenchmarkingLogger> benchmarking_logger,
    server_common::KeyFetcherManagerInterface* key_fetcher_manager,
    CryptoClientWrapperInterface* crypto_client,
    const AsyncReporter* async_reporter,
    const AuctionServiceRuntimeConfig& runtime_config)
    : CodeDispatchReactor<ScoreAdsRequest, ScoreAdsRequest::ScoreAdsRawRequest,
                          ScoreAdsResponse,
                          ScoreAdsResponse::ScoreAdsRawResponse>(
          dispatcher, request, response, key_fetcher_manager, crypto_client,
          runtime_config.encryption_enabled),
      benchmarking_logger_(std::move(benchmarking_logger)),
      async_reporter_(*async_reporter),
      enable_seller_debug_url_generation_(
          runtime_config.enable_seller_debug_url_generation),
      roma_timeout_ms_(runtime_config.roma_timeout_ms),
      log_context_(GetLoggingContext(raw_request_),
                   raw_request_.consented_debug_config(),
                   [this]() { return raw_response_.mutable_debug_info(); }),
      enable_adtech_code_logging_(log_context_.is_consented()),
      enable_report_result_url_generation_(
          runtime_config.enable_report_result_url_generation),
      enable_report_win_url_generation_(
          runtime_config.enable_report_win_url_generation),
      enable_protected_app_signals_(
          runtime_config.enable_protected_app_signals),
      max_allowed_size_debug_url_chars_(
          runtime_config.max_allowed_size_debug_url_bytes),
      max_allowed_size_all_debug_urls_chars_(
          kBytesMultiplyer * runtime_config.max_allowed_size_all_debug_urls_kb),
      enable_report_win_input_noising_(
          runtime_config.enable_report_win_input_noising),
      auction_scope_(raw_request_.top_level_seller().empty()
                         ? AuctionScope::kSingleSeller
                         : AuctionScope::kDeviceComponentSeller) {
  CHECK_OK([this]() {
    PS_ASSIGN_OR_RETURN(metric_context_,
                        metric::AuctionContextMap()->Remove(request_));
    return absl::OkStatus();
  }()) << "AuctionContextMap()->Get(request) should have been called";
}

absl::btree_map<std::string, std::string> ScoreAdsReactor::GetLoggingContext(
    const ScoreAdsRequest::ScoreAdsRawRequest& score_ads_request) {
  const auto& log_context = score_ads_request.log_context();
  return {{kGenerationId, log_context.generation_id()},
          {kSellerDebugId, log_context.adtech_debug_id()}};
}

void ScoreAdsReactor::MayPopulateProtectedAppSignalsDispatchRequests(
    bool enable_debug_reporting,
    const absl::flat_hash_map<std::string, rapidjson::StringBuffer>&
        scoring_signals,
    std::shared_ptr<std::string> auction_config,
    RepeatedPtrField<ProtectedAppSignalsAdWithBidMetadata>&
        protected_app_signals_ad_bids) {
  PS_VLOG(8, log_context_) << __func__;
  while (!protected_app_signals_ad_bids.empty()) {
    std::unique_ptr<ProtectedAppSignalsAdWithBidMetadata> ad(
        protected_app_signals_ad_bids.ReleaseLast());
    if (!scoring_signals.contains(ad->render())) {
      PS_VLOG(5, log_context_)
          << "Skipping protected app signals ad since render "
             "URL is not found in the scoring signals: "
          << ad->render();
      continue;
    }

    DispatchRequest dispatch_request = BuildScoreAdRequest(
        *ad, auction_config, scoring_signals, enable_debug_reporting,
        log_context_, enable_adtech_code_logging_,
        /*device_signals=*/"\"\"");
    auto [unused_it, inserted] = protected_app_signals_ad_data_.emplace(
        dispatch_request.id, std::move(ad));
    if (!inserted) {
      PS_VLOG(2, log_context_)
          << "ProtectedAppSignals ScoreAd Request id conflict detected: "
          << dispatch_request.id;
      continue;
    }

    dispatch_request.tags[kRomaTimeoutMs] = roma_timeout_ms_;
    dispatch_requests_.push_back(std::move(dispatch_request));
  }
}

void ScoreAdsReactor::Execute() {
  benchmarking_logger_->BuildInputBegin();

  PS_VLOG(kEncrypted, log_context_) << "Encrypted ScoreAdsRequest:\n"
                                    << request_->ShortDebugString();
  PS_VLOG(kPlain, log_context_) << "ScoreAdsRawRequest:\n"
                                << raw_request_.DebugString();

  auto ads = raw_request_.ad_bids();
  auto protected_app_signals_ad_bids =
      raw_request_.protected_app_signals_ad_bids();

  DCHECK(raw_request_.protected_app_signals_ad_bids().empty() ||
         enable_protected_app_signals_)
      << "Found protected app signals in score ads request even when feature "
         "is disabled";

  if (auction_scope_ == AuctionScope::kDeviceComponentSeller &&
      !raw_request_.protected_app_signals_ad_bids().empty()) {
    // This path should be unreachable from SFE.
    // Component PA and PAS auctions cannot be done together for now.
    PS_VLOG(1, log_context_)
        << "Finishing RPC: " << kDeviceComponentAuctionWithPAS;
    FinishWithStatus(::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                    kDeviceComponentAuctionWithPAS));
    return;
  }

  absl::StatusOr<absl::flat_hash_map<std::string, rapidjson::StringBuffer>>
      scoring_signals = BuildTrustedScoringSignals(raw_request_, log_context_);

  if (!scoring_signals.ok()) {
    PS_VLOG(1, log_context_) << "No scoring signals found, finishing RPC: "
                             << scoring_signals.status();
    FinishWithStatus(server_common::FromAbslStatus(scoring_signals.status()));
    return;
  }

  std::shared_ptr<std::string> auction_config =
      BuildAuctionConfig(raw_request_);
  bool enable_debug_reporting = enable_seller_debug_url_generation_ &&
                                raw_request_.enable_debug_reporting();
  benchmarking_logger_->BuildInputEnd();
  while (!ads.empty()) {
    std::unique_ptr<AdWithBidMetadata> ad(ads.ReleaseLast());
    if (scoring_signals->contains(ad->render())) {
      DispatchRequest dispatch_request = BuildScoreAdRequest(
          *ad, auction_config, *scoring_signals, enable_debug_reporting,
          log_context_, enable_adtech_code_logging_,
          MakeDeviceSignals(raw_request_.publisher_hostname(),
                            ad->interest_group_owner(), ad->render(),
                            ad->ad_components(),
                            raw_request_.top_level_seller()));
      auto [unused_it, inserted] =
          ad_data_.emplace(dispatch_request.id, std::move(ad));
      if (!inserted) {
        PS_VLOG(2, log_context_) << "Protected Audience ScoreAd Request id "
                                    "conflict detected: "
                                 << dispatch_request.id;
        continue;
      }

      dispatch_request.tags[kRomaTimeoutMs] = roma_timeout_ms_;
      dispatch_requests_.push_back(std::move(dispatch_request));
    }
  }

  MayPopulateProtectedAppSignalsDispatchRequests(
      enable_debug_reporting, *scoring_signals, auction_config,
      protected_app_signals_ad_bids);

  if (dispatch_requests_.empty()) {
    // Internal error so that this is not propagated back to ad server.
    FinishWithStatus(::grpc::Status(grpc::StatusCode::INTERNAL,
                                    kNoAdsWithValidScoringSignals));
    return;
  }
  absl::Time start_js_execution_time = absl::Now();
  auto status = dispatcher_.BatchExecute(
      dispatch_requests_,
      [this, start_js_execution_time](
          const std::vector<absl::StatusOr<DispatchResponse>>& result) {
        int js_execution_time_ms =
            (absl::Now() - start_js_execution_time) / absl::Milliseconds(1);
        LogIfError(metric_context_->LogHistogram<metric::kJSExecutionDuration>(
            js_execution_time_ms));
        ScoreAdsCallback(result);
      });

  if (!status.ok()) {
    LogIfError(metric_context_
                   ->AccumulateMetric<metric::kAuctionErrorCountByErrorCode>(
                       1, metric::kAuctionScoreAdsFailedToDispatchCode));
    PS_VLOG(1, log_context_)
        << "Execution request failed for batch: " << raw_request_.DebugString()
        << status.ToString(absl::StatusToStringMode::kWithEverything);
    LogIfError(
        metric_context_->LogUpDownCounter<metric::kJSExecutionErrorCount>(1));
    FinishWithStatus(
        grpc::Status(grpc::StatusCode::UNKNOWN, status.ToString()));
  }
}

long DebugReportUrlsLength(const ScoreAdsResponse::AdScore& ad_score) {
  if (!ad_score.has_debug_report_urls()) {
    return 0;
  }
  return ad_score.debug_report_urls().auction_debug_win_url().length() +
         ad_score.debug_report_urls().auction_debug_loss_url().length();
}

absl::StatusOr<ScoreAdsResponse::AdScore> ParseScoreAdResponse(
    const rapidjson::Document& score_ad_resp,
    int max_allowed_size_debug_url_chars,
    long max_allowed_size_all_debug_urls_chars,
    long current_all_debug_urls_chars, bool device_component_auction) {
  ScoreAdsResponse::AdScore score_ads_response;
  // Default value.
  score_ads_response.set_allow_component_auction(false);
  if (score_ad_resp.IsNumber()) {
    score_ads_response.set_desirability(score_ad_resp.GetDouble());
    return score_ads_response;
  }

  auto desirability_itr =
      score_ad_resp.FindMember(kDesirabilityPropertyForScoreAd);
  if (desirability_itr == score_ad_resp.MemberEnd() ||
      !desirability_itr->value.IsNumber()) {
    score_ads_response.set_desirability(0.0);
  } else {
    score_ads_response.set_desirability(
        (float)desirability_itr->value.GetFloat());
  }

  // Parse component auction fields.
  if (device_component_auction) {
    auto component_auction_itr =
        score_ad_resp.FindMember(kAllowComponentAuctionPropertyForScoreAd);
    if (component_auction_itr != score_ad_resp.MemberEnd() &&
        component_auction_itr->value.IsBool()) {
      score_ads_response.set_allow_component_auction(
          component_auction_itr->value.GetBool());
    }

    auto ad_metadata_itr =
        score_ad_resp.FindMember(kAdMetadataForComponentAuction);
    if (ad_metadata_itr != score_ad_resp.MemberEnd() &&
        ad_metadata_itr->value.IsString()) {
      score_ads_response.set_ad_metadata(ad_metadata_itr->value.GetString());
    }

    if (ad_metadata_itr != score_ad_resp.MemberEnd() &&
        ad_metadata_itr->value.IsObject()) {
      PS_ASSIGN_OR_RETURN((*score_ads_response.mutable_ad_metadata()),
                          SerializeJsonDoc(ad_metadata_itr->value));
    }

    auto modified_bid_itr =
        score_ad_resp.FindMember(kModifiedBidForComponentAuction);
    if (modified_bid_itr != score_ad_resp.MemberEnd() &&
        modified_bid_itr->value.IsNumber()) {
      score_ads_response.set_bid((float)modified_bid_itr->value.GetFloat());
    }
  }

  auto debug_report_urls_itr =
      score_ad_resp.FindMember(kDebugReportUrlsPropertyForScoreAd);
  if (debug_report_urls_itr == score_ad_resp.MemberEnd()) {
    return score_ads_response;
  }
  DebugReportUrls debug_report_urls;
  if (debug_report_urls_itr->value.HasMember(
          kAuctionDebugWinUrlPropertyForScoreAd) &&
      debug_report_urls_itr->value[kAuctionDebugWinUrlPropertyForScoreAd]
          .IsString()) {
    absl::string_view win_debug_url =
        debug_report_urls_itr->value[kAuctionDebugWinUrlPropertyForScoreAd]
            .GetString();
    int win_url_length = win_debug_url.length();
    if (win_url_length <= max_allowed_size_debug_url_chars &&
        win_url_length + current_all_debug_urls_chars <=
            max_allowed_size_all_debug_urls_chars) {
      debug_report_urls.set_auction_debug_win_url(win_debug_url);
      current_all_debug_urls_chars += win_url_length;
    }
  }
  if (debug_report_urls_itr->value.HasMember(
          kAuctionDebugLossUrlPropertyForScoreAd) &&
      debug_report_urls_itr->value[kAuctionDebugLossUrlPropertyForScoreAd]
          .IsString()) {
    absl::string_view loss_debug_url =
        debug_report_urls_itr->value[kAuctionDebugLossUrlPropertyForScoreAd]
            .GetString();
    int loss_url_length = loss_debug_url.length();
    if (loss_url_length <= max_allowed_size_debug_url_chars &&
        loss_url_length + current_all_debug_urls_chars <=
            max_allowed_size_all_debug_urls_chars) {
      debug_report_urls.set_auction_debug_loss_url(loss_debug_url);
    }
  }
  *score_ads_response.mutable_debug_report_urls() = debug_report_urls;
  return score_ads_response;
}

std::optional<ScoreAdsResponse::AdScore::AdRejectionReason>
ParseAdRejectionReason(const rapidjson::Document& score_ad_resp,
                       absl::string_view interest_group_owner,
                       absl::string_view interest_group_name,
                       log::ContextImpl& log_context) {
  auto reject_reason_itr =
      score_ad_resp.FindMember(kRejectReasonPropertyForScoreAd);
  if (reject_reason_itr == score_ad_resp.MemberEnd() ||
      !reject_reason_itr->value.IsString()) {
    return std::nullopt;
  }
  std::string rejection_reason_str =
      score_ad_resp[kRejectReasonPropertyForScoreAd].GetString();
  SellerRejectionReason rejection_reason =
      ToSellerRejectionReason(rejection_reason_str);
  ScoreAdsResponse::AdScore::AdRejectionReason ad_rejection_reason;
  ad_rejection_reason.set_interest_group_owner(interest_group_owner);
  ad_rejection_reason.set_interest_group_name(interest_group_name);
  ad_rejection_reason.set_rejection_reason(rejection_reason);
  return ad_rejection_reason;
}

void ScoreAdsReactor::PerformReporting(
    const ScoreAdsResponse::AdScore& winning_ad_score, absl::string_view id) {
  std::shared_ptr<std::string> auction_config =
      BuildAuctionConfig(raw_request_);
  ComponentReportingMetadata component_reporting_metadata = {};
  if (auction_scope_ == AuctionScope::kDeviceComponentSeller) {
    component_reporting_metadata = {
        .top_level_seller = raw_request_.top_level_seller(),
        .component_seller = raw_request_.seller()};
  }
  if (auto ad_it = ad_data_.find(id); ad_it != ad_data_.end()) {
    const auto& ad = ad_it->second;
    DispatchReportingRequest(
        *ad, winning_ad_score, id, auction_config,
        kReportingDispatchHandlerFunctionName,
        {.enable_report_win_url_generation = enable_report_win_url_generation_,
         .buyer_signals = raw_request_.per_buyer_signals().at(
             winning_ad_score.interest_group_owner()),
         .join_count = ad->join_count(),
         .recency = ad->recency(),
         .modeling_signals = ad->modeling_signals(),
         .seller = raw_request_.seller(),
         .interest_group_name = winning_ad_score.interest_group_name(),
         .ad_cost = ad->ad_cost()},
        std::optional(component_reporting_metadata), "");
  } else if (auto protected_app_signals_ad_it =
                 protected_app_signals_ad_data_.find(id);
             protected_app_signals_ad_it !=
             protected_app_signals_ad_data_.end()) {
    const auto& ad = protected_app_signals_ad_it->second;
    DispatchReportingRequest(
        *ad, winning_ad_score, id, auction_config,
        kReportingProtectedAppSignalsFunctionName,
        {.enable_report_win_url_generation = enable_report_win_url_generation_,
         .enable_protected_app_signals = enable_protected_app_signals_,
         .buyer_signals = raw_request_.per_buyer_signals().at(
             winning_ad_score.interest_group_owner()),
         .modeling_signals = ad->modeling_signals(),
         .seller = raw_request_.seller(),
         .interest_group_name = winning_ad_score.interest_group_name(),
         .ad_cost = ad->ad_cost()},
        std::optional(component_reporting_metadata), ad->egress_features());
  } else {
    PS_VLOG(1, log_context_)
        << "Following id didn't map to any ProtectedAudience or "
           "ProtectedAppSignals Ad: "
        << id;
    FinishWithStatus(
        grpc::Status(grpc::StatusCode::INTERNAL, kInternalServerError));
  }
}

void ScoreAdsReactor::HandleScoredAd(
    int index, float bid, absl::string_view interest_group_name,
    absl::string_view interest_group_owner,
    const rapidjson::Document& response_json, AdType ad_type,
    ScoreAdsResponse::AdScore& score_ads_response, ScoringData& scoring_data) {
  // Get ad rejection reason before updating the scoring data.
  std::optional<ScoreAdsResponse::AdScore::AdRejectionReason>
      ad_rejection_reason;
  if (!response_json.IsNumber()) {
    // Parse Ad rejection reason and store only if it has value.
    ad_rejection_reason = ParseAdRejectionReason(
        response_json, interest_group_owner, interest_group_name, log_context_);
  }

  score_ads_response.set_interest_group_name(interest_group_name);
  score_ads_response.set_interest_group_owner(interest_group_owner);
  score_ads_response.set_ad_type(ad_type);
  score_ads_response.set_buyer_bid(bid);
  const bool is_valid_ad =
      !ad_rejection_reason.has_value() ||
      ad_rejection_reason->rejection_reason() ==
          SellerRejectionReason::SELLER_REJECTION_REASON_NOT_AVAILABLE;
  // Consider only ads that are not explicitly rejected and the ones that have
  // a positive desirability score.
  if (is_valid_ad && score_ads_response.desirability() >
                         scoring_data.desirability_of_most_desirable_ad) {
    if (auction_scope_ == AuctionScope::kDeviceComponentSeller &&
        !score_ads_response.allow_component_auction()) {
      // Ignore component level winner if it is not allowed to
      // participate in the top level auction.
      // TODO(b/311234165): Add metric for rejected component ads.
      PS_VLOG(1, log_context_)
          << "Skipping component bid as it is not allowed for "
          << interest_group_name << ": " << score_ads_response.DebugString();
      return;
    }
    scoring_data.UpdateWinner(index, score_ads_response);
  }
  scoring_data.score_ad_map[score_ads_response.desirability()].push_back(index);
  ad_scores_.push_back(
      std::make_unique<ScoreAdsResponse::AdScore>(score_ads_response));

  if (is_valid_ad && score_ads_response.desirability() > 0) {
    // Consider scored ad as valid (i.e. not rejected) when it has a positive
    // desirability and either:
    // 1. scoreAd returned a number.
    // 2. scoreAd returned an object but the reject reason was not populated.
    // 3. scoreAd returned an object and the reject reason was explicitly set to
    //    "not-available".
    return;
  }

  // Populate a default rejection reason if needed when we didn't get a positive
  // desirability.
  if (score_ads_response.desirability() <= 0 &&
      !ad_rejection_reason.has_value()) {
    PS_VLOG(5, log_context_)
        << "Non-positive desirability for ad and no rejection reason populated "
           "by seller, providing a default rejection reason";
    ad_rejection_reason = ScoreAdsResponse::AdScore::AdRejectionReason{};
    ad_rejection_reason->set_interest_group_owner(interest_group_owner);
    ad_rejection_reason->set_interest_group_name(interest_group_name);
    ad_rejection_reason->set_rejection_reason(
        SellerRejectionReason::SELLER_REJECTION_REASON_NOT_AVAILABLE);
  }
  scoring_data.ad_rejection_reasons.push_back(*ad_rejection_reason);
  scoring_data.seller_rejected_bid_count += 1;
  LogIfError(
      metric_context_->AccumulateMetric<metric::kAuctionBidRejectedCount>(
          1, ToSellerRejectionReasonString(
                 ad_rejection_reason->rejection_reason())));
}

void ScoreAdsReactor::FindScoredAdType(
    absl::string_view response_id, AdWithBidMetadata** ad_with_bid_metadata,
    ProtectedAppSignalsAdWithBidMetadata**
        protected_app_signals_ad_with_bid_metadata) {
  if (auto ad_it = ad_data_.find(response_id); ad_it != ad_data_.end()) {
    *ad_with_bid_metadata = ad_it->second.get();
  } else if (auto protected_app_signals_ad_it =
                 protected_app_signals_ad_data_.find(response_id);
             protected_app_signals_ad_it !=
             protected_app_signals_ad_data_.end()) {
    *protected_app_signals_ad_with_bid_metadata =
        protected_app_signals_ad_it->second.get();
  }
}

ScoringData ScoreAdsReactor::FindWinningAd(
    const std::vector<absl::StatusOr<DispatchResponse>>& responses) {
  ScoringData scoring_data;
  for (int index = 0; index < responses.size(); ++index) {
    const auto& response = responses[index];
    if (!response.ok()) {
      ABSL_LOG(WARNING) << "Invalid execution (possibly invalid input): "
                        << responses[index].status().ToString(
                               absl::StatusToStringMode::kWithEverything);
      continue;
    }

    absl::StatusOr<rapidjson::Document> response_json =
        ParseAndGetScoreAdResponseJson(enable_adtech_code_logging_,
                                       response->resp, log_context_);

    // Determine what type of ad was scored in this response.
    AdWithBidMetadata* ad = nullptr;
    ProtectedAppSignalsAdWithBidMetadata* protected_app_signals_ad_with_bid =
        nullptr;
    FindScoredAdType(response->id, &ad, &protected_app_signals_ad_with_bid);
    if (!ad && !protected_app_signals_ad_with_bid) {
      // This should never happen but we log here in case there is a bug in our
      // implementation.
      ABSL_LOG(ERROR) << "Scored ad is neither a protected audience ad, nor a "
                         "protected app "
                         "signals ad: "
                      << response->resp;
      continue;
    }

    if (!response_json.ok()) {
      LogWarningForBadResponse(response_json.status(), *response, ad,
                               log_context_);
      continue;
    }

    long current_all_debug_urls_chars = 0;
    auto score_ads_response = ParseScoreAdResponse(
        *response_json, max_allowed_size_debug_url_chars_,
        max_allowed_size_all_debug_urls_chars_, current_all_debug_urls_chars,
        auction_scope_ == AuctionScope::kDeviceComponentSeller);
    if (!score_ads_response.ok()) {
      LogWarningForBadResponse(score_ads_response.status(), *response, ad,
                               log_context_);
      continue;
    }
    current_all_debug_urls_chars += DebugReportUrlsLength(*score_ads_response);

    if (ad) {
      HandleScoredAd(index, ad->bid(), ad->interest_group_name(),
                     ad->interest_group_owner(), *response_json,
                     AdType::AD_TYPE_PROTECTED_AUDIENCE_AD, *score_ads_response,
                     scoring_data);
    } else {
      HandleScoredAd(index, protected_app_signals_ad_with_bid->bid(),
                     /*interest_group_name=*/"",
                     protected_app_signals_ad_with_bid->owner(), *response_json,
                     AdType::AD_TYPE_PROTECTED_APP_SIGNALS_AD,
                     *score_ads_response, scoring_data);
    }
  }
  return scoring_data;
}

void ScoreAdsReactor::PopulateRelevantFieldsInResponse(
    int index_of_most_desirable_ad, absl::string_view request_id,
    ScoreAdsResponse::AdScore& winning_ad) {
  AdWithBidMetadata* ad = nullptr;
  ProtectedAppSignalsAdWithBidMetadata* protected_app_signals_ad_with_bid =
      nullptr;
  FindScoredAdType(request_id, &ad, &protected_app_signals_ad_with_bid);
  // Note: Before the call flow gets here, we would have already verified the
  // winning ad type is one of the expected types and hence we only do a DCHECK
  // here.
  DCHECK(ad || protected_app_signals_ad_with_bid);

  if (ad) {
    winning_ad.set_render(ad->render());
    winning_ad.mutable_component_renders()->Swap(ad->mutable_ad_components());
  } else {
    winning_ad.set_render(protected_app_signals_ad_with_bid->render());
  }
}

void ScoreAdsReactor::PopulateHighestScoringOtherBidsData(
    int index_of_most_desirable_ad,
    const absl::flat_hash_map<float, std::list<int>>& score_ad_map,
    const std::vector<absl::StatusOr<DispatchResponse>>& responses,
    ScoreAdsResponse::AdScore& winning_ad) {
  std::vector<float> scores_list;
  // Logic to calculate the list of highest scoring other bids and
  // corresponding IG owners.
  for (const auto& [score, unused_ad_indices] : score_ad_map) {
    scores_list.push_back(score);
  }

  // Sort the scores in descending order.
  std::sort(scores_list.begin(), scores_list.end(),
            [](int a, int b) { return a > b; });

  // Add all the bids with the top 2 scores (excluding the winner and bids
  // with 0 score) and corresponding interest group owners to
  // ig_owner_highest_scoring_other_bids_map.
  for (int i = 0; i < 2 && i < scores_list.size(); i++) {
    if (scores_list.at(i) == 0) {
      break;
    }

    for (int current_index : score_ad_map.at(scores_list.at(i))) {
      if (index_of_most_desirable_ad == current_index) {
        continue;
      }

      AdWithBidMetadata* ad = nullptr;
      ProtectedAppSignalsAdWithBidMetadata* protected_app_signals_ad_with_bid =
          nullptr;
      FindScoredAdType(responses[current_index]->id, &ad,
                       &protected_app_signals_ad_with_bid);
      DCHECK(ad || protected_app_signals_ad_with_bid);
      auto* highest_scoring_other_bids_map =
          winning_ad.mutable_ig_owner_highest_scoring_other_bids_map();

      if (ad) {
        UpdateHighestScoringOtherBidMap(ad->bid(), ad->interest_group_owner(),
                                        *highest_scoring_other_bids_map);
      } else {
        UpdateHighestScoringOtherBidMap(
            protected_app_signals_ad_with_bid->bid(),
            protected_app_signals_ad_with_bid->owner(),
            *highest_scoring_other_bids_map);
      }
    }
  }
}

// Handles the output of the code execution dispatch.
// Note that the dispatch response value is expected to be a json string
// conforming to the scoreAd function output described here:
// https://github.com/WICG/turtledove/blob/main/FLEDGE.md#23-scoring-bids
void ScoreAdsReactor::ScoreAdsCallback(
    const std::vector<absl::StatusOr<DispatchResponse>>& responses) {
  MayVlogRomaResponses(responses, log_context_);
  benchmarking_logger_->HandleResponseBegin();
  int total_bid_count = static_cast<int>(responses.size());
  LogIfError(metric_context_->AccumulateMetric<metric::kAuctionTotalBidsCount>(
      total_bid_count));
  ScoringData scoring_data = FindWinningAd(responses);
  LogIfError(metric_context_->LogHistogram<metric::kAuctionBidRejectedPercent>(
      (static_cast<double>(scoring_data.seller_rejected_bid_count)) /
      total_bid_count));
  auto& winning_ad = scoring_data.winning_ad;
  // No Ad won.
  if (!winning_ad.has_value()) {
    LogIfError(metric_context_
                   ->AccumulateMetric<metric::kAuctionErrorCountByErrorCode>(
                       1, metric::kAuctionScoreAdsNoAdSelected));
    ABSL_LOG(WARNING) << "No ad was selected as most desirable";
    PerformDebugReporting(winning_ad);
    benchmarking_logger_->HandleResponseEnd();
    EncryptAndFinishOK();
    return;
  }

  // Set the render URL in overall response for the winning ad.
  const int index_of_most_desirable_ad =
      scoring_data.index_of_most_desirable_ad;
  const auto& id = responses[index_of_most_desirable_ad]->id;
  PopulateRelevantFieldsInResponse(index_of_most_desirable_ad, id, *winning_ad);

  PopulateHighestScoringOtherBidsData(index_of_most_desirable_ad,
                                      scoring_data.score_ad_map, responses,
                                      *winning_ad);

  const auto& ad_rejection_reasons = scoring_data.ad_rejection_reasons;
  winning_ad->mutable_ad_rejection_reasons()->Assign(
      ad_rejection_reasons.begin(), ad_rejection_reasons.end());

  PerformDebugReporting(winning_ad);
  *raw_response_.mutable_ad_score() = *winning_ad;

  PS_VLOG(2, log_context_) << "ScoreAdsRawResponse:\n"
                           << raw_response_.DebugString();
  if (!enable_report_result_url_generation_) {
    DCHECK(encryption_enabled_);
    benchmarking_logger_->HandleResponseEnd();
    EncryptAndFinishOK();
    return;
  }
  PerformReporting(*winning_ad, id);
}

void ScoreAdsReactor::ReportingCallback(
    const std::vector<absl::StatusOr<DispatchResponse>>& responses) {
  if (log::PS_VLOG_IS_ON(2)) {
    for (const auto& dispatch_response : responses) {
      PS_VLOG(2, log_context_)
          << "Reporting V8 Response: " << dispatch_response.status();
      if (dispatch_response.ok()) {
        PS_VLOG(2, log_context_) << dispatch_response.value().resp;
      }
    }
  }
  for (const auto& response : responses) {
    if (response.ok()) {
      absl::StatusOr<ReportingResponse> reporting_response =
          ParseAndGetReportingResponse(enable_adtech_code_logging_,
                                       response.value().resp);
      if (!reporting_response.ok()) {
        PS_VLOG(0, log_context_) << "Failed to parse response from Roma ",
            reporting_response.status().ToString(
                absl::StatusToStringMode::kWithEverything);
        continue;
      }
      if (log::PS_VLOG_IS_ON(1) && enable_adtech_code_logging_) {
        for (std::string& log : reporting_response.value().seller_logs) {
          PS_VLOG(1, log_context_)
              << "Log from Seller's execution script:" << log;
        }
        for (std::string& log : reporting_response.value().seller_error_logs) {
          PS_VLOG(1, log_context_)
              << "Error Log from Seller's execution script:" << log;
        }
        for (std::string& log :
             reporting_response.value().seller_warning_logs) {
          PS_VLOG(1, log_context_)
              << "Warning Log from Seller's execution script:" << log;
        }
        for (std::string& log : reporting_response.value().buyer_logs) {
          PS_VLOG(1, log_context_)
              << "Log from Buyer's execution script:" << log;
        }
        for (std::string& log : reporting_response.value().buyer_error_logs) {
          PS_VLOG(1, log_context_)
              << "Error Log from Buyer's execution script:" << log;
        }
        for (std::string& log : reporting_response.value().buyer_warning_logs) {
          PS_VLOG(1, log_context_)
              << "Warning Log from Buyer's execution script:" << log;
        }
      }
      // For component auctions, the reporting urls for seller are set in the
      // component_seller_reporting_urls field. For single seller auctions and
      // top level auctions, the reporting urls are set in the
      // top_level_seller_reporting_urls field.
      if (auction_scope_ == AuctionScope::kDeviceComponentSeller) {
        raw_response_.mutable_ad_score()
            ->mutable_win_reporting_urls()
            ->mutable_component_seller_reporting_urls()
            ->set_reporting_url(reporting_response.value()
                                    .report_result_response.report_result_url);
        for (const auto& [event, interactionReportingUrl] :
             reporting_response.value()
                 .report_result_response.interaction_reporting_urls) {
          raw_response_.mutable_ad_score()
              ->mutable_win_reporting_urls()
              ->mutable_component_seller_reporting_urls()
              ->mutable_interaction_reporting_urls()
              ->try_emplace(event, interactionReportingUrl);
        }

      } else {
        raw_response_.mutable_ad_score()
            ->mutable_win_reporting_urls()
            ->mutable_top_level_seller_reporting_urls()
            ->set_reporting_url(reporting_response.value()
                                    .report_result_response.report_result_url);
        for (const auto& [event, interactionReportingUrl] :
             reporting_response.value()
                 .report_result_response.interaction_reporting_urls) {
          raw_response_.mutable_ad_score()
              ->mutable_win_reporting_urls()
              ->mutable_top_level_seller_reporting_urls()
              ->mutable_interaction_reporting_urls()
              ->try_emplace(event, interactionReportingUrl);
        }
      }
      raw_response_.mutable_ad_score()
          ->mutable_win_reporting_urls()
          ->mutable_buyer_reporting_urls()
          ->set_reporting_url(
              reporting_response.value().report_win_response.report_win_url);

      for (const auto& [event, interactionReportingUrl] :
           reporting_response.value()
               .report_win_response.interaction_reporting_urls) {
        raw_response_.mutable_ad_score()
            ->mutable_win_reporting_urls()
            ->mutable_buyer_reporting_urls()
            ->mutable_interaction_reporting_urls()
            ->try_emplace(event, interactionReportingUrl);
      }
    } else {
      LogIfError(metric_context_
                     ->AccumulateMetric<metric::kAuctionErrorCountByErrorCode>(
                         1, metric::kAuctionScoreAdsDispatchResponseError));
      PS_LOG(WARNING, log_context_)
          << "Invalid execution (possibly invalid input): "
          << response.status().ToString(
                 absl::StatusToStringMode::kWithEverything);
    }
  }

  EncryptAndFinishOK();
}

void ScoreAdsReactor::PerformDebugReporting(
    const std::optional<ScoreAdsResponse::AdScore>& winning_ad_score) {
  PostAuctionSignals post_auction_signals =
      GeneratePostAuctionSignals(winning_ad_score);
  for (const auto& ad_score : ad_scores_) {
    if (ad_score->has_debug_report_urls()) {
      std::string debug_url;
      bool is_win_debug_url = false;
      std::string ig_owner = ad_score->interest_group_owner();
      std::string ig_name = ad_score->interest_group_name();
      auto done_cb = [ig_owner, ig_name](
                         absl::StatusOr<absl::string_view> result) mutable {
        if (result.ok()) {
          PS_VLOG(2) << "Performed debug reporting for:" << ig_owner
                     << ", interest_group: " << ig_name;
        } else {
          PS_VLOG(1) << "Error while performing debug reporting for:"
                     << ig_owner << ", interest_group: " << ig_name
                     << " ,status:" << result.status();
        }
      };
      if (ig_owner == post_auction_signals.winning_ig_owner &&
          ig_name == post_auction_signals.winning_ig_name) {
        debug_url = ad_score->debug_report_urls().auction_debug_win_url();
        is_win_debug_url = true;
      } else {
        debug_url = ad_score->debug_report_urls().auction_debug_loss_url();
      }
      const HTTPRequest http_request = CreateDebugReportingHttpRequest(
          debug_url,
          GetPlaceholderDataForInterestGroup(ig_owner, ig_name,
                                             post_auction_signals),
          is_win_debug_url);
      async_reporter_.DoReport(http_request, done_cb);
    }
  }
}

void ScoreAdsReactor::EncryptAndFinishOK() {
  DCHECK(encryption_enabled_);
  PS_VLOG(kPlain, log_context_) << "ScoreAdsRawResponse:\n"
                                << raw_response_.DebugString();
  EncryptResponse();
  PS_VLOG(kEncrypted, log_context_) << "Encrypted ScoreAdsResponse\n"
                                    << response_->ShortDebugString();
  benchmarking_logger_->HandleResponseEnd();
  FinishWithStatus(grpc::Status::OK);
}

void ScoreAdsReactor::FinishWithStatus(const grpc::Status& status) {
  if (status.error_code() != grpc::StatusCode::OK) {
    metric_context_->SetRequestResult(server_common::ToAbslStatus(status));
  }
  Finish(status);
}

}  // namespace privacy_sandbox::bidding_auction_servers
