// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "services/auction_service/seller_code_fetch_manager.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "services/auction_service/auction_code_fetch_config.pb.h"
#include "services/auction_service/auction_constants.h"
#include "services/auction_service/code_wrapper/buyer_reporting_fetcher.h"
#include "services/auction_service/code_wrapper/seller_code_wrapper.h"
#include "services/common/clients/code_dispatcher/v8_dispatcher.h"
#include "services/common/code_fetch/code_fetcher_interface.h"
#include "services/common/code_fetch/periodic_bucket_fetcher.h"
#include "services/common/code_fetch/periodic_code_fetcher.h"
#include "services/common/util/file_util.h"
#include "src/concurrent/event_engine_executor.h"
#include "src/core/interface/errors.h"
#include "src/util/status_macro/status_macros.h"

#include "seller_code_fetch_manager.h"

using ::google::scp::core::errors::GetErrorMessage;

namespace privacy_sandbox::bidding_auction_servers {
namespace {

constexpr int kJsBlobIndex = 0;

}  // namespace

absl::Status SellerCodeFetchManager::Init() {
  if (udf_config_.fetch_mode() != auction_service::FETCH_MODE_LOCAL) {
    buyer_reporting_fetcher_ = std::make_unique<BuyerReportingFetcher>(
        udf_config_, &buyer_reporting_http_fetcher_, &executor_);
    PS_RETURN_IF_ERROR(buyer_reporting_fetcher_->Start())
        << kBuyerReportingFailedStartup;
  }

  switch (udf_config_.fetch_mode()) {
    case auction_service::FETCH_MODE_LOCAL: {
      return InitializeLocalCodeFetch();
    }
    case auction_service::FETCH_MODE_BUCKET: {
      PS_ASSIGN_OR_RETURN(seller_code_fetcher_, InitializeBucketCodeFetch());
      return absl::OkStatus();
    }
    case auction_service::FETCH_MODE_URL: {
      PS_ASSIGN_OR_RETURN(seller_code_fetcher_, InitializeUrlCodeFetch());
      return absl::OkStatus();
    }
    default: {
      return absl::InvalidArgumentError("Fetch mode invalid.");
    }
  }
}

absl::Status SellerCodeFetchManager::End() {
  if (udf_config_.fetch_mode() != auction_service::FETCH_MODE_LOCAL) {
    buyer_reporting_fetcher_->End();
    seller_code_fetcher_->End();
  }
  return absl::OkStatus();
}

WrapCodeForDispatch SellerCodeFetchManager::GetUdfWrapper() {
  return [this](const std::vector<std::string>& ad_tech_code_blobs) {
    auto protected_auction_reporting =
        buyer_reporting_fetcher_->GetProtectedAuctionReportingByOrigin();
    auto protected_app_signals_reporting =
        buyer_reporting_fetcher_->GetProtectedAppSignalsReportingByOrigin();
    return GetSellerWrappedCode(
        ad_tech_code_blobs[kJsBlobIndex],
        udf_config_.enable_report_result_url_generation(),
        enable_protected_app_signals_,
        udf_config_.enable_report_win_url_generation(),
        protected_auction_reporting, protected_app_signals_reporting);
  };
}

absl::Status SellerCodeFetchManager::InitializeLocalCodeFetch() {
  if (udf_config_.auction_js_path().empty()) {
    return absl::UnavailableError(
        "Local fetch mode requires a non-empty path.");
  }

  PS_ASSIGN_OR_RETURN(auto adtech_code_blob,
                      GetFileContent(udf_config_.auction_js_path(),
                                     /*log_on_error=*/true));

  adtech_code_blob = GetSellerWrappedCode(
      adtech_code_blob, udf_config_.enable_report_result_url_generation(),
      false, {});

  return dispatcher_.LoadSync(kScoreAdBlobVersion, adtech_code_blob);
}

absl::StatusOr<std::unique_ptr<PeriodicBucketFetcher>>
SellerCodeFetchManager::InitializeBucketCodeFetch() {
  PS_RETURN_IF_ERROR(InitBucketClient());

  std::string bucket_name = udf_config_.auction_js_bucket();
  if (udf_config_.auction_js_bucket().empty()) {
    return absl::InvalidArgumentError(
        "Bucket fetch mode requires a non-empty bucket name.");
  } else if (udf_config_.auction_js_bucket_default_blob().empty()) {
    return absl::InvalidArgumentError(
        "Bucket fetch mode requires a non-empty bucket default object "
        "name.");
  }
  auto seller_code_fetcher = std::make_unique<PeriodicBucketFetcher>(
      udf_config_.auction_js_bucket(),
      absl::Milliseconds(udf_config_.url_fetch_period_ms()), &dispatcher_,
      &executor_, GetUdfWrapper(), blob_storage_client_.get());
  PS_RETURN_IF_ERROR(seller_code_fetcher->Start())
      << kSellerUDFLoadFailedStartup;
  return seller_code_fetcher;
}

absl::StatusOr<std::unique_ptr<PeriodicCodeFetcher>>
SellerCodeFetchManager::InitializeUrlCodeFetch() {
  if (udf_config_.auction_js_url().empty()) {
    return absl::InvalidArgumentError(
        "URL fetch mode requires a non-empty url.");
  }
  std::vector<std::string> seller_endpoints = {udf_config_.auction_js_url()};

  auto seller_code_fetcher = std::make_unique<PeriodicCodeFetcher>(
      seller_endpoints, absl::Milliseconds(udf_config_.url_fetch_period_ms()),
      &seller_http_fetcher_, &dispatcher_, &executor_,
      absl::Milliseconds(udf_config_.url_fetch_timeout_ms()), GetUdfWrapper(),
      kScoreAdBlobVersion);
  PS_RETURN_IF_ERROR(seller_code_fetcher->Start())
      << kSellerUDFLoadFailedStartup;
  return seller_code_fetcher;
}

absl::Status SellerCodeFetchManager::InitBucketClient() {
  auto result = blob_storage_client_->Init();
  if (!result.Successful()) {
    return absl::UnavailableError(
        absl::StrFormat("Failed to init BlobStorageClient (status_code: %s)\n",
                        GetErrorMessage(result.status_code)));
  }

  result = blob_storage_client_->Run();
  if (!result.Successful()) {
    return absl::UnavailableError(
        absl::StrFormat("Failed to run BlobStorageClient (status_code: %s)\n",
                        GetErrorMessage(result.status_code)));
  }
  return absl::OkStatus();
}

}  // namespace privacy_sandbox::bidding_auction_servers