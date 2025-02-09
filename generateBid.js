async function generateBids(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  return {
    ad: {
      name: interestGroup.name
    },
    bid: 0.5,
    render: "https://example.com/ad"
  };
}
