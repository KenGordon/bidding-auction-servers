async function generateBid(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  return {
    ad: {
      signals: trustedBiddingSignals
    },
    bid: 0.7,
    render: "https://example.com/ad"
  };
}
