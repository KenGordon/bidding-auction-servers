async function generateBids(interestGroup, auctionSignals, perBuyerSignals, trustedBiddingSignals, browserSignals) {
  return {
    interest_group_name: interestGroup.name,
    bid: 0.5,
    render: "https://example.com/ad" + trustedBiddingSignals[0].value
  };
}
