// Copyright 2024 Google LLC
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

#include "services/common/blob_fetch/blob_fetcher.h"

#include <memory>
#include <utility>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/notification.h"
#include "src/core/interface/async_context.h"
#include "src/core/interface/errors.h"
#include "src/logger/request_context_logger.h"
#include "src/public/core/interface/execution_result.h"
#include "src/public/cpio/interface/blob_storage_client/blob_storage_client_interface.h"
#include "src/public/cpio/proto/blob_storage_service/v1/blob_storage_service.pb.h"
<<<<<<< HEAD
=======
#include "src/util/status_macro/status_macros.h"
>>>>>>> upstream-v3.10.0

using ::google::cmrt::sdk::blob_storage_service::v1::GetBlobRequest;
using ::google::cmrt::sdk::blob_storage_service::v1::GetBlobResponse;
using ::google::cmrt::sdk::blob_storage_service::v1::ListBlobsMetadataRequest;
using ::google::cmrt::sdk::blob_storage_service::v1::ListBlobsMetadataResponse;
using ::google::scp::core::AsyncContext;
using ::google::scp::core::ExecutionResult;
using ::google::scp::core::errors::GetErrorMessage;
using ::google::scp::cpio::BlobStorageClientInterface;

namespace privacy_sandbox::bidding_auction_servers {

BlobFetcher::BlobFetcher(
    absl::string_view bucket_name, server_common::Executor* executor,
    std::unique_ptr<BlobStorageClientInterface> blob_storage_client)
    : bucket_name_(bucket_name),
      executor_(executor),
      blob_storage_client_(std::move(blob_storage_client)) {
<<<<<<< HEAD
  InitAndRunConfigClient();
=======
  absl::Status status = blob_storage_client_->Init();
  CHECK(status.ok()) << "Failed to init BlobStorageClient: " << status;
  status = blob_storage_client_->Run();
  CHECK(status.ok()) << "Failed to run BlobStorageClient: " << status;
>>>>>>> upstream-v3.10.0
}

absl::Status BlobFetcher::FetchSync() {
  absl::Status status;
  absl::Notification done;
  executor_->Run([&status, &done, this]() {
    status = InternalFetch();
    done.Notify();
  });
  done.WaitForNotification();
  return status;
}

<<<<<<< HEAD
void BlobFetcher::InitAndRunConfigClient() {
  auto result = blob_storage_client_->Init();
  CHECK(result.Successful())
      << absl::StrFormat("Failed to init BlobStorageClient (status_code: %s)\n",
                         GetErrorMessage(result.status_code));

  result = blob_storage_client_->Run();
  CHECK(result.Successful())
      << absl::StrFormat("Failed to run BlobStorageClient (status_code: %s)\n",
                         GetErrorMessage(result.status_code));
}

=======
>>>>>>> upstream-v3.10.0
absl::Status BlobFetcher::InternalFetch() {
  absl::Status status;
  std::vector<std::string> blob_names;

  // List all the blobs in the bucket.
  auto list_blobs_request = std::make_shared<ListBlobsMetadataRequest>();
  absl::Notification notification;
  list_blobs_request->mutable_blob_metadata()->set_bucket_name(bucket_name_);
<<<<<<< HEAD
=======
  list_blobs_request->set_exclude_directories(true);
>>>>>>> upstream-v3.10.0
  AsyncContext<ListBlobsMetadataRequest, ListBlobsMetadataResponse>
      list_blobs_context(list_blobs_request, [&status, &blob_names,
                                              &notification](auto& context) {
        if (!context.result.Successful()) {
<<<<<<< HEAD
          PS_VLOG(0) << "Failed to list blobs: "
                     << GetErrorMessage(context.result.status_code);
=======
          PS_LOG(ERROR) << "Failed to list blobs: "
                        << GetErrorMessage(context.result.status_code);
>>>>>>> upstream-v3.10.0
          status = absl::InternalError("Failed to list blobs");
        } else {
          PS_VLOG(10) << "BlobStorageClient ListBlobsMetadata() Response: "
                      << context.response->DebugString();
          for (int i = 0; i < context.response->blob_metadatas_size(); i++) {
            blob_names.push_back(
                context.response->blob_metadatas(i).blob_name());
          }
        }
<<<<<<< HEAD
=======

>>>>>>> upstream-v3.10.0
        // The caller waits for the notification.
        // Please note that the callback might not be called by
        // ListBlobsMetadata.
        // TODO(b/316960066): Inspect the BlobStorageClient code and fix
        // bugs.
        notification.Notify();
      });

<<<<<<< HEAD
  auto list_blobs_execution =
      blob_storage_client_->ListBlobsMetadata(list_blobs_context);
  if (!list_blobs_execution.Successful()) {
    // If ListBlobsMetadata fails fast, we return the error early without
    // waiting for `notification`.
    return absl::InternalError(
        absl::StrCat("BlobStorageClient -> ListBlobsMetadata() failed: ",
                     GetErrorMessage(list_blobs_execution.status_code)));
  }
  notification.WaitForNotification();
  // Checks the error from the callback.
  if (!status.ok()) {
    return status;
  }

  std::vector<Blob> new_file_snapshot;
=======
  // If ListBlobsMetadata fails fast, we return the error early without
  // waiting for `notification`.
  PS_RETURN_IF_ERROR(
      blob_storage_client_->ListBlobsMetadata(list_blobs_context));
  notification.WaitForNotification();

  // Checks the error from the callback.
  PS_RETURN_IF_ERROR(status);

  std::vector<Blob> new_file_snapshot;

>>>>>>> upstream-v3.10.0
  // Fetches all the blobs in the bucket.
  // TODO(b/329674737): Fetch blobs in parallel.
  for (const std::string& blob_name : blob_names) {
    absl::Notification per_blob_notification;
    auto get_blob_request = std::make_shared<GetBlobRequest>();
    get_blob_request->mutable_blob_metadata()->set_bucket_name(bucket_name_);
    get_blob_request->mutable_blob_metadata()->set_blob_name(blob_name);

    AsyncContext<GetBlobRequest, GetBlobResponse> get_blob_context(
        get_blob_request,
        [&status, &new_file_snapshot, &per_blob_notification](auto& context) {
          if (!context.result.Successful()) {
<<<<<<< HEAD
            PS_VLOG(0) << "Failed to fetch blobs: "
                       << GetErrorMessage(context.result.status_code);
=======
            PS_LOG(ERROR) << "Failed to fetch blobs: "
                          << GetErrorMessage(context.result.status_code);
>>>>>>> upstream-v3.10.0
            status = absl::InternalError("Failed to fetch blobs");
          } else {
            // Should not log blob().data(), which can be very large bytes.
            PS_VLOG(10) << "BlobStorageClient GetBlob() Response: "
                        << context.response->blob().metadata().DebugString();

            const std::string& path =
                context.response->blob().metadata().blob_name();
            const std::string& bytes = context.response->blob().data();
            new_file_snapshot.emplace_back(path, bytes);
          }
          // TODO(b/316960066): Inspect the BlobStorageClient code and fix bugs.
          per_blob_notification.Notify();
        });

<<<<<<< HEAD
    auto get_blob_execution = blob_storage_client_->GetBlob(get_blob_context);
    if (!get_blob_execution.Successful()) {
      // If GetBlob fails fast, we return the error early. We update the file
      // snapshot only when all the file fetching is successfully done.
      return absl::InternalError(
          absl::StrCat("BlobStorageClient -> GetBlob() failed: ",
                       GetErrorMessage(get_blob_execution.status_code)));
    }
    per_blob_notification.WaitForNotification();
    // Checks the error from the callback.
    if (!status.ok()) {
      return status;
    }
=======
    // If GetBlob fails fast, we return the error early. We update the file
    // snapshot only when all the file fetching is successfully done.
    PS_RETURN_IF_ERROR(blob_storage_client_->GetBlob(get_blob_context));
    per_blob_notification.WaitForNotification();

    // Checks the error from the callback.
    PS_RETURN_IF_ERROR(status);
>>>>>>> upstream-v3.10.0
  }

  // All the blobs are successfully fetched.
  snapshot_ = std::move(new_file_snapshot);
  return status;
}

}  // namespace privacy_sandbox::bidding_auction_servers
