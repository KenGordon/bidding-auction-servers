function fibonacci(num) {
  if (num <= 1) return 1;
  return fibonacci(num - 1) + fibonacci(num - 2);
}

function generateBid(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals,  deviceSignals) {
  // Do a random amount of work to generate the price:
  const bid = fibonacci(Math.floor(Math.random() * 10 + 1));

    return {'ad': {"arbitraryMetadataField": 1},
            'bid': bid,
            'render': "%s" + interest_group.adRenderIds[0],
            'adComponents': ["adComponentRenderUrlOne", "adComponentRenderUrlTwo"],
            'allowComponentAuction': false};
}
