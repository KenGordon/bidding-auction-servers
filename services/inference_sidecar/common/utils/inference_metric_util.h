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

#ifndef SERVICES_INFERENCE_SIDECAR_COMMON_UTILS_INFERENCE_METRIC_UTIL_H_
#define SERVICES_INFERENCE_SIDECAR_COMMON_UTILS_INFERENCE_METRIC_UTIL_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "proto/inference_sidecar.pb.h"

namespace privacy_sandbox::bidding_auction_servers::inference {

// Adds a metric to the provided PredictResponse object.
void AddMetric(PredictResponse& response, const std::string& key, int32_t value,
               std::optional<std::string> partition = std::nullopt);

}  // namespace privacy_sandbox::bidding_auction_servers::inference

#endif  // SERVICES_INFERENCE_SIDECAR_COMMON_UTILS_INFERENCE_METRIC_UTIL_H_
