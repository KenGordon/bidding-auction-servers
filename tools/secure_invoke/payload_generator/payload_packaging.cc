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

#include "tools/secure_invoke/payload_generator/payload_packaging.h"

#include <google/protobuf/util/json_util.h>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "rapidjson/document.h"
#include "services/common/util/json_util.h"
#include "tools/secure_invoke/payload_generator/payload_packaging_utils.h"

namespace privacy_sandbox::bidding_auction_servers {

namespace {

rapidjson::Document ParseRequestInputJson(absl::string_view json_contents) {
  auto document = ParseJsonString(json_contents);
  CHECK(document.ok()) << document.status();
  CHECK((*document).HasMember(kAuctionConfigField))
      << "Input JSON must contain auction_config";
  CHECK((*document).HasMember(kProtectedAuctionInputField))
      << "Input JSON must contain " << kProtectedAuctionInputField;
  CHECK((*document)[kProtectedAuctionInputField].IsObject())
      << kProtectedAuctionInputField << " must be an object";
  // If old buyer input field is present, replace with new field to prevent
  // collision with field in ProtectedAuctionInput while parsing proto.
  if (!(*document)[kProtectedAuctionInputField].HasMember(
          kBuyerInputMapField) &&
      (*document)[kProtectedAuctionInputField].HasMember(
          kOldBuyerInputMapField)) {
    rapidjson::Value& buyer_map =
        (*document)[kProtectedAuctionInputField][kOldBuyerInputMapField];
    (*document)[kProtectedAuctionInputField].AddMember(
        kBuyerInputMapField, buyer_map, document->GetAllocator());
    (*document)[kProtectedAuctionInputField].RemoveMember(
        kOldBuyerInputMapField);
  }
  CHECK((*document)[kProtectedAuctionInputField].HasMember(kBuyerInputMapField))
      << kProtectedAuctionInputField << " must contain buyer input map";
  return std::move(document.value());
}

// Converts rapid json value to json string.
std::string ValueToJson(rapidjson::Value* value) {
  CHECK(value != nullptr) << "Input value must be non null";
  rapidjson::Document doc;
  doc.SetObject();
  doc.CopyFrom(*value, doc.GetAllocator());
  auto json_str = SerializeJsonDoc(doc);
  CHECK(json_str.ok()) << json_str.status();
  return std::move(json_str.value());
}

SelectAdRequest::AuctionConfig GetAuctionConfig(
    rapidjson::Document* input_json) {
  CHECK(input_json != nullptr) << "Input JSON must be non null";
  rapidjson::Value& auction_config_json = (*input_json)[kAuctionConfigField];
  std::string auction_config_json_str = ValueToJson(&auction_config_json);

  SelectAdRequest::AuctionConfig auction_config;
  google::protobuf::json::ParseOptions parse_options;
  parse_options.ignore_unknown_fields = true;
  auto auction_config_parse = google::protobuf::util::JsonStringToMessage(
      auction_config_json_str, &auction_config, parse_options);
  CHECK(auction_config_parse.ok()) << auction_config_parse;
  return auction_config;
}

ProtectedAuctionInput GetProtectedAuctionInput(
    rapidjson::Document* input_json, bool enable_debug_reporting = false) {
  CHECK(input_json != nullptr) << "Input JSON must be non null";
  rapidjson::Value& protected_auction_json =
      (*input_json)[kProtectedAuctionInputField];
  std::string protected_auction_json_str = ValueToJson(&protected_auction_json);

  ProtectedAuctionInput protected_auction_input;
  google::protobuf::json::ParseOptions parse_options;
  parse_options.ignore_unknown_fields = true;
  auto protected_auction_input_parse =
      google::protobuf::util::JsonStringToMessage(
          protected_auction_json_str, &protected_auction_input, parse_options);
  // Enable debug reporting for all calls from this tool.
  protected_auction_input.set_enable_debug_reporting(enable_debug_reporting);
  CHECK(protected_auction_input_parse.ok()) << protected_auction_input_parse;
  return protected_auction_input;
}

void MayAddProtectedAppSignals(
    google::protobuf::Map<std::string, BuyerInput>& buyer_input) {}

absl::flat_hash_map<std::string, BuyerInput> GetProtectedAppSignals(
    ClientType client_type, absl::string_view protected_app_signals_json) {
  if (client_type == ClientType::CLIENT_TYPE_BROWSER ||
      protected_app_signals_json.empty()) {
    return {};
  }

  auto protected_app_signals_obj = ParseJsonString(protected_app_signals_json);
  CHECK_OK(protected_app_signals_obj);

  absl::flat_hash_map<std::string, BuyerInput> protected_app_signals_map;
  google::protobuf::json::ParseOptions parse_options;
  parse_options.ignore_unknown_fields = true;
  for (auto it = protected_app_signals_obj->MemberBegin();
       it != protected_app_signals_obj->MemberEnd(); ++it) {
    BuyerInput buyer_input_proto;
    auto serialized_buyer_input = SerializeJsonDoc(it->value.GetObject());
    CHECK_OK(serialized_buyer_input);
    auto buyer_input_parse = google::protobuf::util::JsonStringToMessage(
        *serialized_buyer_input, &buyer_input_proto, parse_options);
    CHECK_OK(buyer_input_parse);
    protected_app_signals_map.emplace(it->name.GetString(),
                                      std::move(buyer_input_proto));
  }

  return protected_app_signals_map;
}

google::protobuf::Map<std::string, BuyerInput> GetBuyerInputMap(
    ClientType client_type, rapidjson::Document* input_json,
    absl::string_view protected_app_signals_json) {
  CHECK(input_json != nullptr) << "Input JSON must be non null";
  CHECK(input_json->HasMember(kProtectedAuctionInputField))
      << "Input Must have field " << kProtectedAuctionInputField;
  CHECK(
      (*input_json)[kProtectedAuctionInputField].HasMember(kBuyerInputMapField))
      << "Input " << kProtectedAuctionInputField << " must have field "
      << kBuyerInputMapField;
  rapidjson::Value& buyer_map_json =
      (*input_json)[kProtectedAuctionInputField][kBuyerInputMapField];

  absl::flat_hash_map<std::string, BuyerInput> buyer_input_map;
  absl::flat_hash_map<std::string, BuyerInput> protected_app_signals =
      GetProtectedAppSignals(client_type, protected_app_signals_json);
  for (auto& buyer_input : buyer_map_json.GetObject()) {
    std::string buyer_input_json = ValueToJson(&buyer_input.value);

    google::protobuf::json::ParseOptions parse_options;
    parse_options.ignore_unknown_fields = true;
    BuyerInput buyer_input_proto;
    auto buyer_input_parse = google::protobuf::util::JsonStringToMessage(
        buyer_input_json, &buyer_input_proto, parse_options);
    CHECK(buyer_input_parse.ok()) << buyer_input_parse;

    auto protected_app_signals_it =
        protected_app_signals.find(buyer_input.name.GetString());
    if (protected_app_signals_it != protected_app_signals.end()) {
      buyer_input_proto.set_allocated_protected_app_signals(
          protected_app_signals_it->second.release_protected_app_signals());
      protected_app_signals.erase(protected_app_signals_it);
    }

    buyer_input_map.try_emplace(buyer_input.name.GetString(),
                                std::move(buyer_input_proto));
  }

  buyer_input_map.merge(protected_app_signals);
  return google::protobuf::Map<std::string, BuyerInput>(buyer_input_map.begin(),
                                                        buyer_input_map.end());
}

}  // namespace

std::pair<std::unique_ptr<SelectAdRequest>,
          quiche::ObliviousHttpRequest::Context>
PackagePlainTextSelectAdRequest(absl::string_view input_json_str,
                                ClientType client_type,
                                const HpkeKeyset& keyset,
                                bool enable_debug_reporting,
                                absl::string_view protected_app_signals_json) {
  rapidjson::Document input_json = ParseRequestInputJson(input_json_str);
  google::protobuf::Map<std::string, BuyerInput> buyer_map_proto =
      GetBuyerInputMap(client_type, &input_json, protected_app_signals_json);
  // Encode buyer map.
  absl::StatusOr<google::protobuf::Map<std::string, std::string>>
      encoded_buyer_map;
  switch (client_type) {
    case CLIENT_TYPE_BROWSER:
      encoded_buyer_map = PackageBuyerInputsForBrowser(buyer_map_proto);
      break;
    case CLIENT_TYPE_ANDROID:
      encoded_buyer_map = PackageBuyerInputsForApp(buyer_map_proto);
    default:
      break;
  }
  CHECK(encoded_buyer_map.ok()) << encoded_buyer_map.status();

  ProtectedAuctionInput protected_auction_input =
      GetProtectedAuctionInput(&input_json, enable_debug_reporting);
  // Set encoded BuyerInput.
  protected_auction_input.mutable_buyer_input()->swap(*encoded_buyer_map);
  // Package protected_auction_input.
  auto pa_ciphertext_encryption_context_pair =
      PackagePayload(protected_auction_input, client_type, keyset);
  CHECK(pa_ciphertext_encryption_context_pair.ok())
      << pa_ciphertext_encryption_context_pair.status();
  auto select_ad_request = std::make_unique<SelectAdRequest>();
  *(select_ad_request->mutable_auction_config()) =
      GetAuctionConfig(&input_json);
  select_ad_request->set_protected_auction_ciphertext(
      pa_ciphertext_encryption_context_pair->first);
  select_ad_request->set_client_type(client_type);
  return {std::move(select_ad_request),
          std::move(pa_ciphertext_encryption_context_pair->second)};
}

std::string PackagePlainTextSelectAdRequestToJson(
    absl::string_view input_json_str, ClientType client_type,
    const HpkeKeyset& keyset, bool enable_debug_reporting) {
  auto req =
      std::move(PackagePlainTextSelectAdRequest(input_json_str, client_type,
                                                keyset, enable_debug_reporting)
                    .first);
  std::string select_ad_json;
  auto select_ad_json_status =
      google::protobuf::util::MessageToJsonString(*req, &select_ad_json);
  CHECK(select_ad_json_status.ok()) << select_ad_json_status;
  return select_ad_json;
}

}  // namespace privacy_sandbox::bidding_auction_servers
