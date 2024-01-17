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
    name = "azure_encryption_test",
    size = "large",
    srcs = ["azure_encryption_test.cc"],
    linkstatic = 1,  # AZURE_TODO: Need to revert later. It allows run the test without docker. ./bazel-bin/tools/secure_invoke/secure_invoke_lib_test
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
        "@google_privacysandbox_servers_common//scp/cc/core/utils/src:core_utils",
        "@google_privacysandbox_servers_common//scp/cc/public/cpio/interface:cpio",
        "@google_privacysandbox_servers_common//src/cpp/communication:ohttp_utils",
        "@google_privacysandbox_servers_common//src/cpp/concurrent:executor",
        "@google_privacysandbox_servers_common//src/cpp/encryption/key_fetcher/src:fake_key_fetcher_manager",
        "@google_privacysandbox_servers_common//src/cpp/encryption/key_fetcher/src:key_fetcher_manager",
        "@google_privacysandbox_servers_common//src/cpp/encryption/key_fetcher/src:private_key_fetcher",
        "@google_privacysandbox_servers_common//src/cpp/encryption/key_fetcher/src:public_key_fetcher",
    ],
)
