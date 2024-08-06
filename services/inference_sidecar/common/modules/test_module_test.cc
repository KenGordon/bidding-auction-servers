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

#include "modules/test_module.h"

#include <memory>

#include "absl/status/statusor.h"
#include "gtest/gtest.h"
#include "modules/module_interface.h"
#include "proto/inference_sidecar.pb.h"

namespace privacy_sandbox::bidding_auction_servers::inference {
namespace {

constexpr absl::string_view kModelPath =
    "__main__/testdata/models/tensorflow_1_mib_saved_model.pb";

TEST(TestModule, Success_Predict) {
<<<<<<< HEAD
  std::unique_ptr<ModuleInterface> module = ModuleInterface::Create();
=======
  InferenceSidecarRuntimeConfig config;
  std::unique_ptr<ModuleInterface> module = ModuleInterface::Create(config);
>>>>>>> upstream-v3.10.0
  PredictRequest request;
  auto result = module->Predict(request);
  EXPECT_TRUE(result.ok());
}

TEST(TestModule, Success_RegisterModel) {
<<<<<<< HEAD
  std::unique_ptr<ModuleInterface> module = ModuleInterface::Create();
=======
  InferenceSidecarRuntimeConfig config;
  std::unique_ptr<ModuleInterface> module = ModuleInterface::Create(config);
>>>>>>> upstream-v3.10.0
  RegisterModelRequest request;
  auto result = module->RegisterModel(request);
  EXPECT_TRUE(result.ok());
}

TEST(TestModule, Success_ReadModel) {
<<<<<<< HEAD
  std::unique_ptr<TestModule> module = std::make_unique<TestModule>();
=======
  InferenceSidecarRuntimeConfig config;
  std::unique_ptr<TestModule> module = std::make_unique<TestModule>(config);
>>>>>>> upstream-v3.10.0
  module->set_model_path(kModelPath);
  RegisterModelRequest request;
  auto result = module->RegisterModel(request);
  EXPECT_TRUE(result.ok());
  EXPECT_GT(module->model_size(), 0);
}

<<<<<<< HEAD
=======
TEST(TestModule, Success_ResetModels) {
  InferenceSidecarRuntimeConfig config;
  std::unique_ptr<TestModule> module = std::make_unique<TestModule>(config);
  module->ResetModels();
}

>>>>>>> upstream-v3.10.0
}  // namespace
}  // namespace privacy_sandbox::bidding_auction_servers::inference
