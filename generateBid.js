async function generateBids(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  return {
    ad: {
      name: interestGroup.name
    },
    bid: 0.6,
    render: "https://example.com/ad"
  };
}
