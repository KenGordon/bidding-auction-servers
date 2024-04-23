/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "services/common/util/json_util.h"

#include <vector>

#include "include/gtest/gtest.h"
#include "services/common/test/random.h"

namespace privacy_sandbox::bidding_auction_servers {
namespace {

TEST(ParseJsonString, WorksForValidJsonString) {
  auto test_str = MakeARandomStructJsonString(4);
  absl::StatusOr<rapidjson::Document> output = ParseJsonString(*test_str);
  ASSERT_TRUE(output.ok()) << output.status();
  EXPECT_TRUE(output.value().IsObject());
}

TEST(ParseJsonString, ReturnsInvalidArgumentForInvalidJsonString) {
  std::string test_str = "{" + MakeARandomString();
  absl::StatusOr<rapidjson::Document> output = ParseJsonString(test_str);
  ASSERT_FALSE(output.ok());
  EXPECT_EQ(output.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(SerializeJsonDoc, WorksForValidDocWithSize) {
  std::string key = MakeARandomString();
  std::string value = MakeARandomString();
  std::string expected_output = "{\"" + key + "\":\"" + value + "\"}";

  rapidjson::Document document;
  document.SetObject();
  rapidjson::Value key_v;
  key_v.SetString(key.c_str(), document.GetAllocator());
  rapidjson::Value val_v;
  val_v.SetString(value.c_str(), document.GetAllocator());
  document.AddMember(key_v, val_v.Move(), document.GetAllocator());

  absl::StatusOr<std::shared_ptr<std::string>> output =
      SerializeJsonDoc(document, 20);
  ASSERT_TRUE(output.ok()) << output.status();
  EXPECT_STREQ(output.value()->c_str(), expected_output.c_str());
}

TEST(SerializeJsonDoc, WorksForValidDoc) {
  std::string key = MakeARandomString();
  std::string value = MakeARandomString();
  std::string expected_output = "{\"" + key + "\":\"" + value + "\"}";

  rapidjson::Document document;
  document.SetObject();
  rapidjson::Value key_v;
  key_v.SetString(key.c_str(), document.GetAllocator());
  rapidjson::Value val_v;
  val_v.SetString(value.c_str(), document.GetAllocator());
  document.AddMember(key_v, val_v, document.GetAllocator());

  absl::StatusOr<std::string> output = SerializeJsonDoc(document);
  ASSERT_TRUE(output.ok()) << output.status();
  EXPECT_STREQ(output.value().c_str(), expected_output.c_str());
}

TEST(SerializeJsonDoc, GetStringMember_WorksForKeyPresentInDocument) {
  std::string json_str = R"json({"key": "value"})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();

  auto actual_value = GetStringMember(*document, "key");
  ASSERT_TRUE(actual_value.ok()) << actual_value.status();
  EXPECT_EQ(*actual_value, "value");
}

TEST(SerializeJsonDoc, GetStringMember_FailsOnEmptyStringVal) {
  std::string json_str = R"json({"key": ""})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();

  auto actual_value = GetStringMember(*document, "key");
  EXPECT_FALSE(actual_value.ok());
}

TEST(SerializeJsonDoc, GetStringMember_ConditionallyAllowsEmptyStringVal) {
  std::string json_str = R"json({"key": ""})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();

  auto actual_value = GetStringMember(*document, "key", /*is_empty_ok=*/true);
  ASSERT_TRUE(actual_value.ok()) << actual_value.status();
  EXPECT_TRUE(actual_value->empty()) << *actual_value;
}

TEST(SerializeJsonDoc, GetStringMember_FailsOnMissingKey) {
  std::string json_str = R"json({"key": "val"})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();

  auto actual_value = GetStringMember(*document, "NotPresentKey");
  EXPECT_FALSE(actual_value.ok());
}

TEST(SerializeJsonDoc, GetStringMember_FailsOnNonStringVal) {
  std::string json_str = R"json({"key": 123})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();

  auto actual_value = GetStringMember(*document, "key");
  EXPECT_FALSE(actual_value.ok());
}

// Function to compare a rapidjson::GenericArray with a std::vector
bool areArraysEqual(const rapidjson::GenericArray<
                        true, rapidjson::GenericValue<rapidjson::UTF8<>>>& arr1,
                    const std::vector<std::string>& arr2) {
  if (arr1.Size() != arr2.size()) {
    return false;
  }

  for (rapidjson::SizeType i = 0; i < arr1.Size(); ++i) {
    if (arr1[i].GetString() != arr2[i]) {
      return false;
    }
  }

  return true;
}

TEST(SerializeJsonDoc, GetArrayMember_WorksForKeyPresentInDocument) {
  std::string json_str = R"json({"key": ["0.32", "0.12", "0.98"]})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();

  auto actual_value = GetArrayMember(*document, "key");
  ASSERT_TRUE(actual_value.ok()) << actual_value.status();
  const std::vector<std::string> expectedArray = {"0.32", "0.12", "0.98"};
  ASSERT_TRUE(areArraysEqual(actual_value.value(), expectedArray));
}

TEST(SerializeJsonDoc, GetArrayMember_FailsOnMissingKey) {
  std::string json_str = R"json({"key": ["0.32", "0.12", "0.98"]})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();
  auto actual_value = GetArrayMember(*document, "NotPresentKey");
  EXPECT_FALSE(actual_value.ok());
}

TEST(SerializeJsonDoc, GetArrayMember_FailsOnNonArrayVal) {
  std::string json_str = R"json({"key": "val"})json";
  auto document = ParseJsonString(json_str);
  ASSERT_TRUE(document.ok()) << document.status();

  auto actual_value = GetArrayMember(*document, "key");
  EXPECT_FALSE(actual_value.ok());
}

}  // namespace
}  // namespace privacy_sandbox::bidding_auction_servers
