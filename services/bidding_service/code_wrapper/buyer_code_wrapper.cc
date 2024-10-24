
//  Copyright 2023 Google LLC
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
#include "services/bidding_service/code_wrapper/buyer_code_wrapper.h"

#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "services/bidding_service/constants.h"
#include "services/common/loggers/request_context_impl.h"

namespace privacy_sandbox::bidding_auction_servers {
namespace {

void AppendFeatureFlagValue(std::string& feature_flags,
                            absl::string_view feature_name,
                            bool is_feature_enabled) {
  absl::string_view enable_feature = kFeatureDisabled;
  if (is_feature_enabled) {
    enable_feature = kFeatureEnabled;
  }
  feature_flags.append(
      absl::StrCat("\"", feature_name, "\": ", enable_feature));
}

std::string WasmBytesToJavascript(absl::string_view wasm_bytes) {
  std::string hex_array = "";

  for (const uint8_t& byte :
       std::vector<uint8_t>(wasm_bytes.begin(), wasm_bytes.end())) {
    absl::StrAppend(&hex_array, absl::StrFormat("%#x,", byte));
  }
  // In javascript, it is ok to leave a comma after the last element in the
  // array.

  return absl::StrFormat(kWasmModuleTemplate, hex_array);
}

absl::string_view GetGenerateBidArgs(AuctionType auction_type) {
  switch (auction_type) {
    case AuctionType::kProtectedAudience:
      return kProtectedAudienceGenerateBidsArgs;
    case AuctionType::kProtectedAppSignals:
      return kProtectedAppSignalsGenerateBidsArgs;
    default:
      PS_VLOG(1) << "Unsupported auction type: " << absl::StrCat(auction_type);
      return "";
  }
}

}  // namespace

std::string GetBuyerWrappedCode(absl::string_view ad_tech_js,
                                absl::string_view ad_tech_wasm,
                                AuctionType auction_type,
                                absl::string_view auction_specific_setup) {
  absl::string_view args = GetGenerateBidArgs(auction_type);
  return absl::StrCat(
      WasmBytesToJavascript(ad_tech_wasm),
      absl::Substitute(kEntryFunction, args, auction_specific_setup),
      ad_tech_js);
}

std::string GetProtectedAppSignalsGenericBuyerWrappedCode(
    absl::string_view ad_tech_js, absl::string_view ad_tech_wasm,
    absl::string_view function_name, absl::string_view args) {
  return absl::StrCat(WasmBytesToJavascript(ad_tech_wasm),
                      absl::Substitute(kPrepareDataForAdRetrievalEntryFunction,
                                       function_name, args),
                      ad_tech_js);
}

std::string GetFeatureFlagJson(bool enable_logging,
                               bool enable_debug_url_generation) {
  std::string feature_flags = "{";
  AppendFeatureFlagValue(feature_flags, kFeatureLogging, enable_logging);
  feature_flags.append(",");
  AppendFeatureFlagValue(feature_flags, kFeatureDebugUrlGeneration,
                         enable_debug_url_generation);
  feature_flags.append("}");
  return feature_flags;
}
}  // namespace privacy_sandbox::bidding_auction_servers
