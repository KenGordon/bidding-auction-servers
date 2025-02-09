async function generateBids(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  return {
    ad: {
      name: interestGroup,
      signals: trustedBiddingSignals,
    },
    bid: 0.7,
    render: "https://example.com/ad"
  };
}
