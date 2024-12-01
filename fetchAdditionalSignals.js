// Copyright (C) Microsoft Corporation. All rights reserved.
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

function generateBids(interest_groups, auction_signals, buyer_signals, trusted_bidding_signals, device_signals) {
  // Reshaped into an AdWithBid.
  const batchKVGetValuesRequest = {
    requests: [
      {
        server_info: { server_name: 'KV_SERVER' },
        get_values_request: {
          client_version: 'v2',
          metadata: {
            hostname: 'example.com',
          },
          partitions: [
            {
              id: 0,
              compressionGroupId: 0,
              arguments: [
                {
                  tags: ['structured', 'groupNames'],
                  data: ['hello'],
                },
                {
                  tags: ['custom', 'keys'],
                  data: ['key1'],
                },
              ],
            },
          ],
          consented_debug_config: {
            is_consented: true,
            token: 'debug_token',
          },
          log_context: {
            generation_id: 'client_UUID',
            adtech_debug_id: 'adtech_debug_test',
          },
        },
      },
    ],
  };

  const jsonRequest = JSON.stringify(batchKVGetValuesRequest);
  const fetchAdditionalSignalsResult = fetchAdditionalSignals(jsonRequest);
  console.log(fetchAdditionalSignalsResult);

  return {
    render: '%s' + interest_groups.adRenderIds[0],
    ad: { arbitraryMetadataField: 1 },
    bid: 10,
    allowComponentAuction: false,
  };
}

//await generateBid({ adRenderIds: ["A"]});
