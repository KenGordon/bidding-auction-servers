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

#include <utility>

#include <google/protobuf/util/message_differencer.h>

#include "api/bidding_auction_servers.grpc.pb.h"
#include "include/gmock/gmock.h"
#include "include/gtest/gtest.h"
#include "services/common/compression/gzip.h"
#include "services/common/test/random.h"
#include "services/common/util/json_util.h"
#include "services/seller_frontend_service/util/select_ad_reactor_test_utils.h"
#include "services/seller_frontend_service/util/web_utils.h"
#include "src/cpp/communication/encoding_utils.h"
#include "src/cpp/communication/ohttp_utils.h"
#include "tools/secure_invoke/payload_generator/payload_packaging_utils.h"

namespace privacy_sandbox::bidding_auction_servers {

namespace {

constexpr char kSellerOriginDomain[] = "seller.com";
constexpr char kTestProtectedAppSignals[] = R"JSON({
   "ad_tech_A" : {
      "protected_app_signals" : {
         "app_install_signals" : "/gH/AQ==",
         "encoding_version" : 0
      }
   }
})JSON";

rapidjson::Document ProtoToDocument(const google::protobuf::Message& message) {
  std::string json_string;
  auto message_convert_status =
      google::protobuf::util::MessageToJsonString(message, &json_string);
  CHECK(message_convert_status.ok()) << message_convert_status;
  auto doc = ParseJsonString(json_string);
  CHECK(doc.ok()) << doc.status();
  return std::move(*doc);
}

// Creates a valid input json doc.
std::string GetValidInput(const SelectAdRequest& expected_output) {
  rapidjson::Document input;
  input.SetObject();

  rapidjson::Value protected_audience_doc;
  protected_audience_doc.SetObject();
  rapidjson::Value buyerMapValue;
  buyerMapValue.SetObject();
  protected_audience_doc.AddMember(kBuyerInputMapField, buyerMapValue,
                                   input.GetAllocator());

  // Copy auction config from expected output.
  auto document = ProtoToDocument(expected_output.auction_config());
  input.AddMember(kAuctionConfigField, document, input.GetAllocator());
  input.AddMember(kProtectedAuctionInputField, protected_audience_doc,
                  input.GetAllocator());

  auto input_str = SerializeJsonDoc(input);
  CHECK(input_str.ok()) << input_str.status();
  return input_str.value();
}

TEST(PaylodPackagingTest, FailsOnEmptyJson) {
  HpkeKeyset keyset;
  EXPECT_DEATH(
      PackagePlainTextSelectAdRequestToJson("", CLIENT_TYPE_BROWSER, keyset),
      "");
}

TEST(PaylodPackagingTest, FailsOnInvalidJson) {
  HpkeKeyset keyset;
  EXPECT_DEATH(PackagePlainTextSelectAdRequestToJson(
                   "random-string", CLIENT_TYPE_BROWSER, keyset),
               "");
}

TEST(PaylodPackagingTest, FailsOnEmptyInputJson) {
  rapidjson::Document input;
  input.SetObject();

  auto input_str = SerializeJsonDoc(input);
  CHECK(input_str.ok()) << input_str.status();
  HpkeKeyset keyset;
  EXPECT_DEATH(PackagePlainTextSelectAdRequestToJson(
                   input_str.value(), CLIENT_TYPE_BROWSER, keyset),
               "");
}

TEST(PaylodPackagingTest, FailsOnInputJsonMissingProtectedAudience) {
  rapidjson::Document input;
  input.SetObject();
  rapidjson::Value auction_config;
  auction_config.SetObject();
  input.AddMember(kAuctionConfigField, auction_config, input.GetAllocator());

  auto input_str = SerializeJsonDoc(input);
  CHECK(input_str.ok()) << input_str.status();
  HpkeKeyset keyset;
  EXPECT_DEATH(PackagePlainTextSelectAdRequestToJson(
                   input_str.value(), CLIENT_TYPE_BROWSER, keyset),
               "");
}

TEST(PaylodPackagingTest, FailsOnInputJsonMissingBuyerInputMap) {
  rapidjson::Document input;
  input.SetObject();

  rapidjson::Value auction_config;
  auction_config.SetObject();
  input.AddMember(kAuctionConfigField, auction_config, input.GetAllocator());

  rapidjson::Value protected_audience_doc;
  protected_audience_doc.SetObject();
  input.AddMember(kProtectedAuctionInputField, protected_audience_doc,
                  input.GetAllocator());

  auto input_str = SerializeJsonDoc(input);
  CHECK(input_str.ok()) << input_str.status();
  HpkeKeyset keyset;
  EXPECT_DEATH(PackagePlainTextSelectAdRequestToJson(
                   input_str.value(), CLIENT_TYPE_BROWSER, keyset),
               "");
}

TEST(PaylodPackagingTest, HandlesOldBuyerInputMapKey) {
  rapidjson::Document input;
  input.SetObject();

  rapidjson::Value auction_config;
  auction_config.SetObject();
  input.AddMember(kAuctionConfigField, auction_config, input.GetAllocator());

  rapidjson::Value protected_audience_doc;
  protected_audience_doc.SetObject();
  rapidjson::Value buyerMapValue;
  buyerMapValue.SetObject();
  protected_audience_doc.AddMember(kOldBuyerInputMapField, buyerMapValue,
                                   input.GetAllocator());
  input.AddMember(kProtectedAuctionInputField, protected_audience_doc,
                  input.GetAllocator());

  auto input_str = SerializeJsonDoc(input);
  CHECK(input_str.ok()) << input_str.status();
  HpkeKeyset keyset;
  PackagePlainTextSelectAdRequestToJson(input_str.value(), CLIENT_TYPE_BROWSER,
                                        keyset);
}

TEST(PaylodPackagingTest, FailsOnInputJsonMissingAuctionConfig) {
  rapidjson::Document input;
  input.SetObject();
  rapidjson::Value protected_audience_doc;
  protected_audience_doc.SetObject();
  rapidjson::Value buyerMapValue;
  buyerMapValue.SetObject();
  protected_audience_doc.AddMember(kBuyerInputMapField, buyerMapValue,
                                   input.GetAllocator());
  input.AddMember(kProtectedAuctionInputField, protected_audience_doc,
                  input.GetAllocator());

  auto input_str = SerializeJsonDoc(input);
  CHECK(input_str.ok()) << input_str.status();
  HpkeKeyset keyset;
  EXPECT_DEATH(PackagePlainTextSelectAdRequestToJson(
                   input_str.value(), CLIENT_TYPE_BROWSER, keyset),
               "");
}

TEST(PaylodPackagingTest, CopiesAuctionConfigFromSourceJson) {
  auto protected_audience_input =
      MakeARandomProtectedAuctionInput<ProtectedAuctionInput>();
  SelectAdRequest expected =
      MakeARandomSelectAdRequest(kSellerOriginDomain, protected_audience_input);
  std::string input = GetValidInput(expected);

  HpkeKeyset keyset;
  std::string output =
      PackagePlainTextSelectAdRequestToJson(input, CLIENT_TYPE_BROWSER, keyset);
  SelectAdRequest actual;
  auto parse_output =
      google::protobuf::util::JsonStringToMessage(output, &actual);
  ASSERT_TRUE(parse_output.ok()) << parse_output;

  google::protobuf::util::MessageDifferencer diff;
  std::string difference;
  diff.ReportDifferencesToString(&difference);
  EXPECT_TRUE(diff.Compare(actual.auction_config(), expected.auction_config()))
      << difference;
}

TEST(PaylodPackagingTest, PassesTopLevelSellerForComponentAuction) {
  absl::string_view top_level_seller = "https://toplevel-seller.com";
  auto protected_audience_input =
      MakeARandomProtectedAuctionInput<ProtectedAuctionInput>();
  SelectAdRequest expected =
      MakeARandomSelectAdRequest(kSellerOriginDomain, protected_audience_input);
  expected.mutable_auction_config()->set_top_level_seller(top_level_seller);
  std::string input = GetValidInput(expected);

  HpkeKeyset keyset;
  std::string output =
      PackagePlainTextSelectAdRequestToJson(input, CLIENT_TYPE_BROWSER, keyset);
  SelectAdRequest actual;
  auto parse_output =
      google::protobuf::util::JsonStringToMessage(output, &actual);
  ASSERT_TRUE(parse_output.ok()) << parse_output;
  EXPECT_EQ(actual.auction_config().top_level_seller(), top_level_seller);
}

TEST(PaylodPackagingTest, SetsTheCorrectClientType) {
  auto protected_audience_input =
      MakeARandomProtectedAuctionInput<ProtectedAuctionInput>();
  SelectAdRequest expected =
      MakeARandomSelectAdRequest(kSellerOriginDomain, protected_audience_input);
  auto input = GetValidInput(expected);

  HpkeKeyset keyset;
  std::string output =
      PackagePlainTextSelectAdRequestToJson(input, CLIENT_TYPE_BROWSER, keyset);
  SelectAdRequest actual;
  auto parse_output =
      google::protobuf::util::JsonStringToMessage(output, &actual);
  ASSERT_TRUE(parse_output.ok()) << parse_output;
  EXPECT_EQ(actual.client_type(), ClientType::CLIENT_TYPE_BROWSER);
}

TEST(PaylodPackagingTest, SetsTheCorrectDebugReportingFlag) {
  bool enable_debug_reporting = true;
  auto input =
      R"JSON({"auction_config":{"sellerSignals":"{\"seller_signal\": \"1698245045006099572\"}","auctionSignals":"{\"auction_signal\": \"1698245045006100642\"}","buyerList":["1698245045005905922"],"seller":"seller.com","perBuyerConfig":{"1698245045005905922":{"buyerSignals":"1698245045006101412"}},"buyerTimeoutMs":1000},"raw_protected_audience_input":{"raw_buyer_input":{"ad_tech_A.com":{"interestGroups":[{"name":"1698245045006110232","biddingSignalsKeys":["1698245045006110482","1698245045006110862"],"adRenderIds":["ad_render_id_1698245045006122582","ad_render_id_1698245045006123002","ad_render_id_1698245045006123242","ad_render_id_1698245045006123472","ad_render_id_1698245045006123772","ad_render_id_1698245045006124002","ad_render_id_1698245045006124212","ad_render_id_1698245045006124412","ad_render_id_1698245045006124672"],"userBiddingSignals":"{\"1698245045006112422\":\"1698245045006112622\",\"1698245045006113232\":\"1698245045006113422\",\"1698245045006111322\":\"1698245045006111702\",\"1698245045006112802\":\"1698245045006112972\",\"1698245045006112032\":\"1698245045006112252\"}","browserSignals":{"joinCount":"8","bidCount":"41","recency":"1698245045","prevWins":"[[1698245045,\"ad_render_id_1698245045006122582\"],[1698245045,\"ad_render_id_1698245045006123002\"],[1698245045,\"ad_render_id_1698245045006123242\"],[1698245045,\"ad_render_id_1698245045006123472\"],[1698245045,\"ad_render_id_1698245045006123772\"],[1698245045,\"ad_render_id_1698245045006124002\"],[1698245045,\"ad_render_id_1698245045006124212\"],[1698245045,\"ad_render_id_1698245045006124412\"],[1698245045,\"ad_render_id_1698245045006124672\"]]"}}]}}}})JSON";

  HpkeKeyset keyset;
  auto select_ad_reqcurrent_all_debug_urls_chars =
      std::move(PackagePlainTextSelectAdRequest(input, CLIENT_TYPE_BROWSER,
                                                keyset, enable_debug_reporting))
          .first;

  absl::StatusOr<server_common::EncapsulatedRequest>
      parsed_encapsulated_request = server_common::ParseEncapsulatedRequest(
          select_ad_reqcurrent_all_debug_urls_chars
              ->protected_auction_ciphertext());
  ASSERT_TRUE(parsed_encapsulated_request.ok())
      << parsed_encapsulated_request.status();

  // Decrypt.
  server_common::PrivateKey private_key;
  private_key.key_id = std::to_string(keyset.key_id);
  private_key.private_key = GetHpkePrivateKey(keyset.private_key);
  auto decrypted_response = server_common::DecryptEncapsulatedRequest(
      private_key, *parsed_encapsulated_request);
  ASSERT_TRUE(decrypted_response.ok()) << decrypted_response.status();

  absl::StatusOr<server_common::DecodedRequest> decoded_request =
      server_common::DecodeRequestPayload(
          decrypted_response->GetPlaintextData());
  ASSERT_TRUE(decoded_request.ok()) << decoded_request.status();

  // Decode.
  ErrorAccumulator error_accumulator;
  absl::StatusOr<ProtectedAuctionInput> actual = Decode<ProtectedAuctionInput>(
      decoded_request->compressed_data, error_accumulator);
  ASSERT_TRUE(actual.ok()) << actual.status();

  EXPECT_TRUE(actual.value().enable_debug_reporting());
}

TEST(PaylodPackagingTest, HandlesProtectedAppSignals) {
  log::PS_VLOG_IS_ON(0, 10);
  auto input = R"JSON(
    {
       "auction_config" : {
          "auction_signals" : "{\"a\":\"1\"}",
          "buyer_list" : [
             "ad_tech_A"
          ],
          "buyer_timeout_ms" : 1,
          "per_buyer_config" : {
             "ad_tech_A" : {
                "buyer_debug_id" : "buyer_debug_id",
                "buyer_signals" : "{\"h3\": \"1\"}"
             }
          },
          "seller" : "ad_tech_B",
          "seller_debug_id" : "seller_debug_id",
          "seller_signals" : "[10137]"
       },
       "client_type" : "CLIENT_TYPE_ANDROID",
       "raw_protected_audience_input" : {
          "enable_debug_reporting" : true,
          "generation_id" : "1",
          "publisher_name" : "test.com",
          "raw_buyer_input" : {
            "ad_tech_A": {
            "interest_groups": [
               {
                "ad_render_ids": [
                 "1"
                ],
                "bidding_signals_keys": [
                 "2"
                ],
                "name": "3",
                "user_bidding_signals": "[4]"
               }
              ]
            }
          }
       }
    })JSON";
  HpkeKeyset keyset;
  auto select_ad_req =
      std::move(PackagePlainTextSelectAdRequest(
                    input, CLIENT_TYPE_ANDROID, keyset,
                    /*enable_debug_reporting=*/true, kTestProtectedAppSignals)
                    .first);

  auto parsed_encapsulated_request = server_common::ParseEncapsulatedRequest(
      select_ad_req->protected_auction_ciphertext());
  ASSERT_TRUE(parsed_encapsulated_request.ok())
      << parsed_encapsulated_request.status();

  // Decrypt.
  server_common::PrivateKey private_key;
  private_key.key_id = std::to_string(keyset.key_id);
  private_key.private_key = GetHpkePrivateKey(keyset.private_key);
  auto decrypted_response = server_common::DecryptEncapsulatedRequest(
      private_key, *parsed_encapsulated_request);
  ASSERT_TRUE(decrypted_response.ok()) << decrypted_response.status();

  absl::StatusOr<server_common::DecodedRequest> decoded_request =
      server_common::DecodeRequestPayload(
          decrypted_response->GetPlaintextData());
  ASSERT_TRUE(decoded_request.ok()) << decoded_request.status();

  // Decode.
  ProtectedAuctionInput protected_auction_input;
  ASSERT_TRUE(protected_auction_input.ParseFromArray(
      decoded_request->compressed_data.data(),
      decoded_request->compressed_data.size()));

  const auto& buyer_input = protected_auction_input.buyer_input();
  ASSERT_NE(buyer_input.find("ad_tech_A"), buyer_input.end())
      << protected_auction_input.DebugString();
  const auto& found_buyer_input = buyer_input.at("ad_tech_A");
  absl::StatusOr<std::string> decompressed_buyer_input =
      GzipDecompress(found_buyer_input);
  ASSERT_TRUE(decompressed_buyer_input.ok())
      << decompressed_buyer_input.status();
  BuyerInput decoded_buyer_input;
  ASSERT_TRUE(decoded_buyer_input.ParseFromArray(
      decompressed_buyer_input->data(), decompressed_buyer_input->size()))
      << protected_auction_input.DebugString();
  EXPECT_TRUE(decoded_buyer_input.has_protected_app_signals());
  EXPECT_TRUE(!decoded_buyer_input.protected_app_signals()
                   .app_install_signals()
                   .empty());
}

}  // namespace

}  // namespace privacy_sandbox::bidding_auction_servers
