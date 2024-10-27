async function generateBid(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  // Extract relevant information from signals
  const { adMetadata } = interestGroup;
  const { renderUrl, bidAmount } = adMetadata || {};

  // Set a default bid if no bid amount is provided
  const bid = bidAmount || 1.0;

  // Return bid details in JSON format
  return JSON.stringify({
      ad: {
          renderUrl,
          metadata: {
              // Metadata is optional but can be used for additional ad info
              category: adMetadata.category || "general",
              advertiser: adMetadata.advertiser || "unknown"
          }
      },
      bid,
      render: renderUrl,
      adComponents: interestGroup.adComponents || [], // Optional ad components
      allowComponentAuction: true // If multi-level auctions are allowed
  });
}
