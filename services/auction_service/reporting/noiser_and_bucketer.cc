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
//  limitations under the License
#include "services/auction_service/reporting/noiser_and_bucketer.h"

#include <cmath>
#include <cstdint>
#include <limits>

#include "absl/status/statusor.h"
#include "openssl/rand.h"
#include "src/cpp/util/status_macro/status_macros.h"

namespace privacy_sandbox::bidding_auction_servers {

// Uses OpenSSL's RAND_bytes to generate a 64 bit unsigned random integer.
absl::StatusOr<uint64_t> RandUint64() {
  uint64_t rand_64;
  if (RAND_bytes(reinterpret_cast<uint8_t*>(&rand_64), sizeof(rand_64)) != 1) {
    return absl::InternalError("Error generating number.");
  }
  return rand_64;
}

// Generates a 64 bit unsigned random integer within [0,range].
absl::StatusOr<uint64_t> RandGenerator(uint64_t range) {
  // We must discard random results above this number, as they would
  // make the random generator non-uniform (consider e.g. if
  // MAX_UINT64 was 7 and range was 5, then a result of 1 would be twice
  // as likely as a result of 3 or 4).
  uint64_t max_acceptable_value =
      (std::numeric_limits<uint64_t>::max() / range) * range - 1;

  uint64_t rand_unit64;
  do {
    PS_ASSIGN_OR_RETURN(rand_unit64, RandUint64());
  } while (rand_unit64 > max_acceptable_value);

  return rand_unit64 % range;
}

// Generates a random integer within the range of [min,max]
absl::StatusOr<int> RandInt(int min, int max) {
  if (min >= max) {
    return absl::InternalError("Invalid range for random number generation.");
  }
  uint64_t range = static_cast<uint64_t>(max - min) + 1;
  // |range| is at most UINT_MAX + 1, so the result of RandGenerator(range)
  // is at most UINT_MAX.  Hence it's safe to cast it from uint64_t to int64_t.
  int rand_unit64;
  PS_ASSIGN_OR_RETURN(rand_unit64, RandGenerator(range));
  return rand_unit64 + min;
}

uint8_t BucketJoinCount(int32_t join_count) {
  if (join_count < 1) {
    join_count = 1;
  }

  if (join_count <= 10) {
    return join_count;
  } else if (join_count <= 20) {
    return 11;
  } else if (join_count <= 30) {
    return 12;
  } else if (join_count <= 40) {
    return 13;
  } else if (join_count <= 50) {
    return 14;
  } else if (join_count <= 100) {
    return 15;
  }

  return 16;
}

uint8_t BucketRecency(long recency) {
  if (recency < 0) {
    recency = 0;
  }

  if (recency < 10) {
    return recency;
  } else if (recency < 15) {
    return 10;
  } else if (recency < 20) {
    return 11;
  } else if (recency < 30) {
    return 12;
  } else if (recency < 40) {
    return 13;
  } else if (recency < 50) {
    return 14;
  } else if (recency < 60) {
    return 15;
  } else if (recency < 75) {
    return 16;
  } else if (recency < 90) {
    return 17;
  } else if (recency < 105) {
    return 18;
  } else if (recency < 120) {
    return 19;
  } else if (recency < 240) {
    return 20;
  } else if (recency < 720) {
    return 21;
  } else if (recency < 1440) {
    return 22;
  } else if (recency < 2160) {
    return 23;
  } else if (recency < 2880) {
    return 24;
  } else if (recency < 4320) {
    return 25;
  } else if (recency < 5760) {
    return 26;
  } else if (recency < 10080) {
    return 27;
  } else if (recency < 20160) {
    return 28;
  } else if (recency < 30240) {
    return 29;
  } else if (recency < 40320) {
    return 30;
  }

  return 31;
}

// Noises 1/100 inputs. If noised, returns a random integer in the range of
// [min,max). If not noised, returns the input as it is.
template <typename T>
absl::StatusOr<T> Noise(T input, int min, int max) {
  absl::StatusOr<int> rand_one_percent_int = RandInt(0, 100);
  if (!rand_one_percent_int.ok()) {
    return rand_one_percent_int;
  }
  if (rand_one_percent_int.value() == 1) {
    absl::StatusOr<int> rand_int = RandInt(min, max);
    if (rand_int.ok()) {
      return static_cast<T>(rand_int.value());
    }
  }
  return input;
}

// Noises and masks ModelingSignals input for reportWin.
// modeling_signals are noised 1 in 100 times. If noised, a random integer
// between 0 and 0x0FFF will be returned. Applies a mask of 0x0FFF to retain
// only 12 bits.
absl::StatusOr<uint16_t> NoiseAndMaskModelingSignals(
    uint16_t modeling_signals) {
  constexpr uint16_t kMask = 0x0FFF;
  return Noise(modeling_signals & kMask, 0, kMask);
}

absl::StatusOr<uint8_t> NoiseAndBucketJoinCount(int32_t join_count) {
  return Noise(BucketJoinCount(join_count), 1, 16);
}

absl::StatusOr<uint8_t> NoiseAndBucketRecency(long recency) {
  return Noise(BucketRecency(recency), 0, 31);
}

}  // namespace privacy_sandbox::bidding_auction_servers
