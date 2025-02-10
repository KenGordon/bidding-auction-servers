async function generateBids(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  return {
    ad: {
      name: interestGroup
    },
    bid: 0.7,
    render: "https://example.com/ad"
  };
}
