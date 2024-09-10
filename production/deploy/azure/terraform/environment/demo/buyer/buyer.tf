# Portions Copyright (c) Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

locals {
  environment     = "demo"
  operator        = "tf"
  region          = "centralindia"
  subscription_id = "7ca35580-fc67-469c-91a7-68b38569ca6e"
  tenant_id       = "72f988bf-86f1-41af-91ab-2d7cd011db47"
}

module "buyer" {
  source          = "../../../modules/buyer"
  environment     = local.environment
  operator        = local.operator
  region          = local.region
  subscription_id = local.subscription_id
  tenant_id       = local.tenant_id
}
