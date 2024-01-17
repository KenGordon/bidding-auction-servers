# GCP

Please see the GCP build and packaging steps
[here](https://github.com/privacysandbox/fledge-docs/blob/main/bidding_auction_services_gcp_guide.md#step-1-packaging).
For deployment, please see
[here](https://github.com/privacysandbox/bidding-auction-servers/tree/main/production/deploy/gcp/terraform/environment/demo).

# AWS

Please see the AWS build and packaging steps
[here](https://github.com/privacysandbox/fledge-docs/blob/main/bidding_auction_services_aws_guide.md#step-1-packaging).
For deployment, please see
[here](https://github.com/privacysandbox/bidding-auction-servers/tree/main/production/deploy/aws/terraform/environment/demo).

# Azure confidential container instances

## Build docker image

```shell
./production/packaging/build_and_test_all_in_docker --service-path bidding_service --service-path seller_frontend_service --service-path buyer_frontend_service --service-path auction_service --config=local_azure --no-precommit --no-tests --azure-image-tag <ENV_NAME> --azure-image-repo ${DOCKER_REPO}  --build-flavor prod
```

-   switch `prod` to `non_prod` for debugging build that turn on all vlog.

-   `${DOCKER_REPO}` is where to store the images such as `us-docker.pkg.dev/project-id/services`

-   `${ENV_NAME}` should match `environment` in terraform deploy.

After images are built, the container security policy will be saved in
`dist/azure/${SERVICE_PATH}.rego`. You can then generate a proposal containing the container
security policy and send the proposal to the coordinators.

> Note: For this Alpha release, Edge and Azure engineers would act as the Coordinators to run the
> Key Management Systems that provision keys for encryption / decryption.
