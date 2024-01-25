# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:defs.bzl", "cc_test")

package(
    default_visibility = [
        "//visibility:public",
    ],
    licenses = ["notice"],
)

cc_test(
    name = "aad_accesstoken",
    size = "large",
    srcs = ["aad_accesstoken.cc"],
    tags = [
        "flaky",
    ],
    deps = [
        "@com_github_google_quiche//quiche:oblivious_http_unstable_api",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_github_google_glog//:glog",
        "@google_privacysandbox_servers_common//scp/cc/core/utils/src:core_utils",
        "@google_privacysandbox_servers_common//scp/cc/public/cpio/interface:cpio",
        "@google_privacysandbox_servers_common//src/cpp/concurrent:executor",
        "@google_privacysandbox_servers_common//src/cpp/accesstoken/src:accesstoken_fetcher",       
    ],
)
