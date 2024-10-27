async function generateBid(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  return {
    ad: {
        renderUrl: "https://example.com/ad",
        metadata: { category: "test" }
    },
    bid: 0.5,
    render: "https://example.com/ad"
  };
}
