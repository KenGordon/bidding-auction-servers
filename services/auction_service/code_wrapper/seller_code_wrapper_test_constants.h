//  Copyright 2023 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
#ifndef FLEDGE_SERVICES_SELLER_CODE_WRAPPER_TEST_CONSTANTS_H_
#define FLEDGE_SERVICES_SELLER_CODE_WRAPPER_TEST_CONSTANTS_H_

#include "absl/strings/string_view.h"

namespace privacy_sandbox::bidding_auction_servers {
constexpr char kBuyerOrigin[] = "http://buyer1.com";
constexpr char kTestReportResultUrl[] = "http://test.com";
constexpr char kTestComponentReportResultUrl[] =
    "http://test.com&topLevelSeller=topLevelSeller&componentSeller=http://"
    "seller.com";
constexpr char kTestInteractionEvent[] = "clickEvent";
constexpr char kTestInteractionReportingUrl[] = "http://click.com";
constexpr char kTestReportWinUrl[] =
    "http://test.com?seller=http://"
    "seller.com&interestGroupName=testInterestGroupName&adCost=2&"
    "modelingSignals=4&recency=3&joinCount=5";

constexpr absl::string_view kBuyerBaseCodeSimple =
    R"JS_CODE(reportWin = function(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals){
})JS_CODE";

constexpr absl::string_view kBuyerBaseCode =
    R"JS_CODE(reportWin = function(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals){
        var test_render_url = buyerReportingSignals.renderUrl
        var test_render_url = buyerReportingSignals.renderURL
        if(buyerReportingSignals.seller==null || buyerReportingSignals.seller == undefined || buyerReportingSignals.seller == ""){
          console.error("Missing seller in input to reportWin")
          return
        }
        if(buyerReportingSignals.interestGroupName == "" || buyerReportingSignals.interestGroupName == undefined
            || buyerReportingSignals.interestGroupName == null){
          console.error("Missing interestGroupName in input to reportWin")
          return
        }
        if(buyerReportingSignals.adCost == 0 || buyerReportingSignals.adCost == -1
            || buyerReportingSignals.adCost == undefined
            || buyerReportingSignals.adCost == null){
          console.error("Missing adCost in input to reportWin")
          return
        }
        var reportWinUrl = "http://test.com?seller="+buyerReportingSignals.seller+
                    "&interestGroupName="+buyerReportingSignals.interestGroupName+
                    "&adCost="+buyerReportingSignals.adCost+"&modelingSignals="+
                    buyerReportingSignals.modelingSignals+"&recency="+buyerReportingSignals.recency+
                    "&madeHighestScoringOtherBid="+buyerReportingSignals.madeHighestScoringOtherBid+
                    "&joinCount="+buyerReportingSignals.joinCount+"&signalsForWinner="+signalsForWinner+
                    "&perBuyerSignals="+perBuyerSignals+"&auctionSignals="+auctionSignals;

        console.log("Logging from ReportWin");
        console.error("Logging error from ReportWin")
        console.warn("Logging warning from ReportWin")
        sendReportTo(reportWinUrl)
        registerAdBeacon({"clickEvent":"http://click.com"})
    }
)JS_CODE";

constexpr absl::string_view kProtectedAppSignalsBuyerBaseCode =
    R"JS_CODE(reportWin = function(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, egressFeatures){
      console.log("Testing Protected App Signals");
      sendReportTo("http://test.com");
      registerAdBeacon({"clickEvent":"http://click.com"});
      return "testSignalsForWinner";
    }
)JS_CODE";

constexpr absl::string_view kSellerBaseCode = R"JS_CODE(
    function fibonacci(num) {
      if (num <= 1) return 1;
      return fibonacci(num - 1) + fibonacci(num - 2);
    }

    function scoreAd(ad_metadata, bid, auction_config, scoring_signals, device_signals, directFromSellerSignals){
      // Do a random amount of work to generate the score:
      const score = fibonacci(Math.floor(Math.random() * 10 + 1));
      console.log("Logging from ScoreAd")
      console.error("Logging error from ScoreAd")
      console.warn("Logging warn from ScoreAd")
      return {
        desirability: score,
        allow_component_auction: false
      }
    }
    function reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals){
        console.log("Logging from ReportResult");
        if(sellerReportingSignals.topLevelSeller === undefined || sellerReportingSignals.topLevelSeller.length === 0){
          sendReportTo("http://test.com")
        } else {
          sendReportTo("http://test.com&topLevelSeller="+sellerReportingSignals.topLevelSeller+"&componentSeller="+sellerReportingSignals.componentSeller)
        }
        registerAdBeacon({"clickEvent":"http://click.com"})
        return "testSignalsForWinner"
    }
)JS_CODE";

constexpr absl::string_view kComponentAuctionCode = R"JS_CODE(
    function scoreAd(ad_metadata, bid, auction_config, scoring_signals, device_signals, directFromSellerSignals){
      return {
        ad: device_signals["topLevelSeller"],
        desirability: 1,
        bid: 2,
        allowComponentAuction: true
      }
    }
    function reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals){
        console.log("Logging from ReportResult");
        if(sellerReportingSignals.topLevelSeller === undefined || sellerReportingSignals.topLevelSeller.length === 0){
          sendReportTo("http://test.com")
        } else {
          sendReportTo("http://test.com&topLevelSeller="+sellerReportingSignals.topLevelSeller+"&componentSeller="+sellerReportingSignals.componentSeller)
        }
        registerAdBeacon({"clickEvent":"http://click.com"})
        return "testSignalsForWinner"
    }

)JS_CODE";

constexpr absl::string_view kSkipAdComponentAuctionCode = R"JS_CODE(
    function scoreAd(ad_metadata, bid, auction_config, scoring_signals, device_signals, directFromSellerSignals){
      return {
        ad: device_signals["topLevelSeller"],
        desirability: 1,
        bid: 2,
        allowComponentAuction: false
      }
    }
)JS_CODE";

constexpr absl::string_view kExpectedFinalCode = R"JS_CODE(
    function scoreAdEntryFunction(adMetadata, bid, auctionConfig, trustedScoringSignals,
                                browserSignals, directFromSellerSignals, featureFlags){
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(featureFlags.enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }

      var forDebuggingOnly_auction_loss_url = undefined;
      var forDebuggingOnly_auction_win_url = undefined;
      const forDebuggingOnly = {};
      forDebuggingOnly.reportAdAuctionLoss = function(url){
        forDebuggingOnly_auction_loss_url = url;
      }
      forDebuggingOnly.reportAdAuctionWin = function(url){
        forDebuggingOnly_auction_win_url = url;
      }
      globalThis.forDebuggingOnly = forDebuggingOnly;

      var scoreAdResponse = {};
      try {
        scoreAdResponse = scoreAd(adMetadata, bid, auctionConfig,
              trustedScoringSignals, browserSignals, directFromSellerSignals);
      } catch({error, message}) {
          console.error("[Error: " + error + "; Message: " + message + "]");
      } finally {
        if( featureFlags.enable_debug_url_generation &&
              (forDebuggingOnly_auction_loss_url
                  || forDebuggingOnly_auction_win_url)) {
          scoreAdResponse.debugReportUrls = {
            auctionDebugLossUrl: forDebuggingOnly_auction_loss_url,
            auctionDebugWinUrl: forDebuggingOnly_auction_win_url
          }
        }
      }
      return {
        response: scoreAdResponse,
        logs: ps_logs,
        errors: ps_errors,
        warnings: ps_warns
      }
    }

    //Handler method to call adTech provided reportResult method and wrap the
    // response with reportResult url and interaction reporting urls.
    function reportingEntryFunction(auctionConfig, sellerReportingSignals, directFromSellerSignals, enable_logging, buyerReportingMetadata, ) {
    ps_signalsForWinner = ""
    var ps_report_result_response = {
        reportResultUrl : "",
        interactionReportingUrls : {},
        sendReportToInvoked : false,
        registerAdBeaconInvoked : false,
      }
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }
      globalThis.sendReportTo = function sendReportTo(url){
        if(ps_report_result_response.sendReportToInvoked) {
          throw new Error("sendReportTo function invoked more than once");
        }
        ps_report_result_response.reportResultUrl = url;
        ps_report_result_response.sendReportToInvoked = true;
      }
      globalThis.registerAdBeacon = function registerAdBeacon(eventUrlMap){
        if(ps_report_result_response.registerAdBeaconInvoked) {
          throw new Error("registerAdBeaconInvoked function invoked more than once");
        }
        ps_report_result_response.interactionReportingUrls=eventUrlMap;
        ps_report_result_response.registerAdBeaconInvoked = true;
      }
      ps_signalsForWinner = reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals);
      try{
      if(buyerReportingMetadata.enableReportWinUrlGeneration){
        var buyerOrigin = buyerReportingMetadata.buyerOrigin
        var functionSuffix = buyerOrigin.replace(/[^a-zA-Z0-9 ]/g, "")
        var auctionSignals = auctionConfig.auctionSignals
        var buyerReportingSignals = sellerReportingSignals
        buyerReportingSignals.interestGroupName = buyerReportingMetadata.interestGroupName
        buyerReportingSignals.madeHighestScoringOtherBid = buyerReportingMetadata.madeHighestScoringOtherBid
        buyerReportingSignals.joinCount = buyerReportingMetadata.joinCount
        buyerReportingSignals.recency = buyerReportingMetadata.recency
        buyerReportingSignals.modelingSignals = buyerReportingMetadata.modelingSignals
        perBuyerSignals = buyerReportingMetadata.perBuyerSignals
        buyerReportingSignals.seller = buyerReportingMetadata.seller
        buyerReportingSignals.adCost = buyerReportingMetadata.adCost
        // Absence of interest group indicates that this is a protected app
        // signals ad.
        if (buyerReportingMetadata.enableProtectedAppSignals &&
            (buyerReportingSignals.interestGroupName === null ||
             buyerReportingSignals.interestGroupName.trim() === "")) {
          functionSuffix += "ProtectedAppSignals";
        }
        var reportWinFunction = "reportWinWrapper"+functionSuffix+"(auctionSignals, perBuyerSignals, ps_signalsForWinner, buyerReportingSignals,"+
                              "directFromSellerSignals, enable_logging, )"
        var reportWinResponse = eval(reportWinFunction)
        return {
          reportResultResponse: ps_report_result_response,
          sellerLogs: ps_logs,
          sellerErrors: ps_errors,
          sellerWarnings: ps_warns,
          reportWinResponse: reportWinResponse.response,
          buyerLogs: reportWinResponse.buyerLogs,
          buyerErrors: reportWinResponse.buyerErrors,
          buyerWarnings: reportWinResponse.buyerWarnings,
      }
      }
      } catch(ex){
        console.error(ex.message)
      }
      return {
        reportResultResponse: ps_report_result_response,
        sellerLogs: ps_logs,
        sellerErrors: ps_errors,
        sellerWarnings: ps_warns,
      }
    }

    // Handler method to call adTech provided reportWin method and wrap the
    // response with reportWin url and interaction reporting urls.
    function reportWinWrapperhttpbuyer1com(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, enable_logging, ) {
      var ps_report_win_response = {
        reportWinUrl : "",
        interactionReportingUrls : {},
        sendReportToInvoked : false,
        registerAdBeaconInvoked : false,
      }
      var ps_buyer_logs = [];
      var ps_buyer_error_logs = [];
      var ps_buyer_warning_logs = [];
      if(enable_logging){
        console.log = function(...args) {
          ps_buyer_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_buyer_error_logs.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_buyer_warning_logs.push(JSON.stringify(args))
        }
      }
      globalThis.sendReportTo = function sendReportTo(url){
        if(ps_report_win_response.sendReportToInvoked) {
          throw new Error("sendReportTo function invoked more than once");
        }
        ps_report_win_response.reportWinUrl = url;
        ps_report_win_response.sendReportToInvoked = true;
      }
      globalThis.registerAdBeacon = function registerAdBeacon(eventUrlMap){
        if(ps_report_win_response.registerAdBeaconInvoked) {
          throw new Error("registerAdBeaconInvoked function invoked more than once");
        }
        ps_report_win_response.interactionReportingUrls = eventUrlMap;
        ps_report_win_response.registerAdBeaconInvoked = true;
      }
      {
      reportWin = function(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals){
        var test_render_url = buyerReportingSignals.renderUrl
        var test_render_url = buyerReportingSignals.renderURL
        if(buyerReportingSignals.seller==null || buyerReportingSignals.seller == undefined || buyerReportingSignals.seller == ""){
          console.error("Missing seller in input to reportWin")
          return
        }
        if(buyerReportingSignals.interestGroupName == "" || buyerReportingSignals.interestGroupName == undefined
            || buyerReportingSignals.interestGroupName == null){
          console.error("Missing interestGroupName in input to reportWin")
          return
        }
        if(buyerReportingSignals.adCost == 0 || buyerReportingSignals.adCost == -1
            || buyerReportingSignals.adCost == undefined
            || buyerReportingSignals.adCost == null){
          console.error("Missing adCost in input to reportWin")
          return
        }
        var reportWinUrl = "http://test.com?seller="+buyerReportingSignals.seller+
                    "&interestGroupName="+buyerReportingSignals.interestGroupName+
                    "&adCost="+buyerReportingSignals.adCost+"&modelingSignals="+
                    buyerReportingSignals.modelingSignals+"&recency="+buyerReportingSignals.recency+
                    "&madeHighestScoringOtherBid="+buyerReportingSignals.madeHighestScoringOtherBid+
                    "&joinCount="+buyerReportingSignals.joinCount+"&signalsForWinner="+signalsForWinner+
                    "&perBuyerSignals="+perBuyerSignals+"&auctionSignals="+auctionSignals;

        console.log("Logging from ReportWin");
        console.error("Logging error from ReportWin")
        console.warn("Logging warning from ReportWin")
        sendReportTo(reportWinUrl)
        registerAdBeacon({"clickEvent":"http://click.com"})
    }

      }
      try{
      reportWin(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, )
      } catch(ex){
        console.error(ex.message)
      }
      return {
        response: ps_report_win_response,
        buyerLogs: ps_buyer_logs,
        buyerErrors: ps_buyer_error_logs,
        buyerWarnings: ps_buyer_warning_logs
      }
    }

    function fibonacci(num) {
      if (num <= 1) return 1;
      return fibonacci(num - 1) + fibonacci(num - 2);
    }

    function scoreAd(ad_metadata, bid, auction_config, scoring_signals, device_signals, directFromSellerSignals){
      // Do a random amount of work to generate the score:
      const score = fibonacci(Math.floor(Math.random() * 10 + 1));
      console.log("Logging from ScoreAd")
      console.error("Logging error from ScoreAd")
      console.warn("Logging warn from ScoreAd")
      return {
        desirability: score,
        allow_component_auction: false
      }
    }
    function reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals){
        console.log("Logging from ReportResult");
        if(sellerReportingSignals.topLevelSeller === undefined || sellerReportingSignals.topLevelSeller.length === 0){
          sendReportTo("http://test.com")
        } else {
          sendReportTo("http://test.com&topLevelSeller="+sellerReportingSignals.topLevelSeller+"&componentSeller="+sellerReportingSignals.componentSeller)
        }
        registerAdBeacon({"clickEvent":"http://click.com"})
        return "testSignalsForWinner"
    }
)JS_CODE";

constexpr absl::string_view kExpectedProtectedAppSignalsFinalCode = R"JS_CODE(
    function scoreAdEntryFunction(adMetadata, bid, auctionConfig, trustedScoringSignals,
                                browserSignals, directFromSellerSignals, featureFlags){
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(featureFlags.enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }

      var forDebuggingOnly_auction_loss_url = undefined;
      var forDebuggingOnly_auction_win_url = undefined;
      const forDebuggingOnly = {};
      forDebuggingOnly.reportAdAuctionLoss = function(url){
        forDebuggingOnly_auction_loss_url = url;
      }
      forDebuggingOnly.reportAdAuctionWin = function(url){
        forDebuggingOnly_auction_win_url = url;
      }
      globalThis.forDebuggingOnly = forDebuggingOnly;

      var scoreAdResponse = {};
      try {
        scoreAdResponse = scoreAd(adMetadata, bid, auctionConfig,
              trustedScoringSignals, browserSignals, directFromSellerSignals);
      } catch({error, message}) {
          console.error("[Error: " + error + "; Message: " + message + "]");
      } finally {
        if( featureFlags.enable_debug_url_generation &&
              (forDebuggingOnly_auction_loss_url
                  || forDebuggingOnly_auction_win_url)) {
          scoreAdResponse.debugReportUrls = {
            auctionDebugLossUrl: forDebuggingOnly_auction_loss_url,
            auctionDebugWinUrl: forDebuggingOnly_auction_win_url
          }
        }
      }
      return {
        response: scoreAdResponse,
        logs: ps_logs,
        errors: ps_errors,
        warnings: ps_warns
      }
    }

    //Handler method to call adTech provided reportResult method and wrap the
    // response with reportResult url and interaction reporting urls.
    function reportingEntryFunctionProtectedAppSignals(auctionConfig, sellerReportingSignals, directFromSellerSignals, enable_logging, buyerReportingMetadata, egressFeatures) {
    ps_signalsForWinner = ""
    var ps_report_result_response = {
        reportResultUrl : "",
        interactionReportingUrls : {},
        sendReportToInvoked : false,
        registerAdBeaconInvoked : false,
      }
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }
      globalThis.sendReportTo = function sendReportTo(url){
        if(ps_report_result_response.sendReportToInvoked) {
          throw new Error("sendReportTo function invoked more than once");
        }
        ps_report_result_response.reportResultUrl = url;
        ps_report_result_response.sendReportToInvoked = true;
      }
      globalThis.registerAdBeacon = function registerAdBeacon(eventUrlMap){
        if(ps_report_result_response.registerAdBeaconInvoked) {
          throw new Error("registerAdBeaconInvoked function invoked more than once");
        }
        ps_report_result_response.interactionReportingUrls=eventUrlMap;
        ps_report_result_response.registerAdBeaconInvoked = true;
      }
      ps_signalsForWinner = reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals);
      try{
      if(buyerReportingMetadata.enableReportWinUrlGeneration){
        var buyerOrigin = buyerReportingMetadata.buyerOrigin
        var functionSuffix = buyerOrigin.replace(/[^a-zA-Z0-9 ]/g, "")
        var auctionSignals = auctionConfig.auctionSignals
        var buyerReportingSignals = sellerReportingSignals
        buyerReportingSignals.interestGroupName = buyerReportingMetadata.interestGroupName
        buyerReportingSignals.madeHighestScoringOtherBid = buyerReportingMetadata.madeHighestScoringOtherBid
        buyerReportingSignals.joinCount = buyerReportingMetadata.joinCount
        buyerReportingSignals.recency = buyerReportingMetadata.recency
        buyerReportingSignals.modelingSignals = buyerReportingMetadata.modelingSignals
        perBuyerSignals = buyerReportingMetadata.perBuyerSignals
        buyerReportingSignals.seller = buyerReportingMetadata.seller
        buyerReportingSignals.adCost = buyerReportingMetadata.adCost
        // Absence of interest group indicates that this is a protected app
        // signals ad.
        if (buyerReportingMetadata.enableProtectedAppSignals &&
            (buyerReportingSignals.interestGroupName === null ||
             buyerReportingSignals.interestGroupName.trim() === "")) {
          functionSuffix += "ProtectedAppSignals";
        }
        var reportWinFunction = "reportWinWrapper"+functionSuffix+"(auctionSignals, perBuyerSignals, ps_signalsForWinner, buyerReportingSignals,"+
                              "directFromSellerSignals, enable_logging, egressFeatures)"
        var reportWinResponse = eval(reportWinFunction)
        return {
          reportResultResponse: ps_report_result_response,
          sellerLogs: ps_logs,
          sellerErrors: ps_errors,
          sellerWarnings: ps_warns,
          reportWinResponse: reportWinResponse.response,
          buyerLogs: reportWinResponse.buyerLogs,
          buyerErrors: reportWinResponse.buyerErrors,
          buyerWarnings: reportWinResponse.buyerWarnings,
      }
      }
      } catch(ex){
        console.error(ex.message)
      }
      return {
        reportResultResponse: ps_report_result_response,
        sellerLogs: ps_logs,
        sellerErrors: ps_errors,
        sellerWarnings: ps_warns,
      }
    }

    // Handler method to call adTech provided reportWin method and wrap the
    // response with reportWin url and interaction reporting urls.
    function reportWinWrapperhttpbuyer1comProtectedAppSignals(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, enable_logging, egressFeatures) {
      var ps_report_win_response = {
        reportWinUrl : "",
        interactionReportingUrls : {},
        sendReportToInvoked : false,
        registerAdBeaconInvoked : false,
      }
      var ps_buyer_logs = [];
      var ps_buyer_error_logs = [];
      var ps_buyer_warning_logs = [];
      if(enable_logging){
        console.log = function(...args) {
          ps_buyer_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_buyer_error_logs.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_buyer_warning_logs.push(JSON.stringify(args))
        }
      }
      globalThis.sendReportTo = function sendReportTo(url){
        if(ps_report_win_response.sendReportToInvoked) {
          throw new Error("sendReportTo function invoked more than once");
        }
        ps_report_win_response.reportWinUrl = url;
        ps_report_win_response.sendReportToInvoked = true;
      }
      globalThis.registerAdBeacon = function registerAdBeacon(eventUrlMap){
        if(ps_report_win_response.registerAdBeaconInvoked) {
          throw new Error("registerAdBeaconInvoked function invoked more than once");
        }
        ps_report_win_response.interactionReportingUrls = eventUrlMap;
        ps_report_win_response.registerAdBeaconInvoked = true;
      }
      {
      reportWinProtectedAppSignals = function(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, egressFeatures){
      console.log("Testing Protected App Signals");
      sendReportTo("http://test.com");
      registerAdBeacon({"clickEvent":"http://click.com"});
      return "testSignalsForWinner";
    }

      }
      try{
      reportWinProtectedAppSignals(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, egressFeatures)
      } catch(ex){
        console.error(ex.message)
      }
      return {
        response: ps_report_win_response,
        buyerLogs: ps_buyer_logs,
        buyerErrors: ps_buyer_error_logs,
        buyerWarnings: ps_buyer_warning_logs
      }
    }

    //Handler method to call adTech provided reportResult method and wrap the
    // response with reportResult url and interaction reporting urls.
    function reportingEntryFunction(auctionConfig, sellerReportingSignals, directFromSellerSignals, enable_logging, buyerReportingMetadata, ) {
    ps_signalsForWinner = ""
    var ps_report_result_response = {
        reportResultUrl : "",
        interactionReportingUrls : {},
        sendReportToInvoked : false,
        registerAdBeaconInvoked : false,
      }
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }
      globalThis.sendReportTo = function sendReportTo(url){
        if(ps_report_result_response.sendReportToInvoked) {
          throw new Error("sendReportTo function invoked more than once");
        }
        ps_report_result_response.reportResultUrl = url;
        ps_report_result_response.sendReportToInvoked = true;
      }
      globalThis.registerAdBeacon = function registerAdBeacon(eventUrlMap){
        if(ps_report_result_response.registerAdBeaconInvoked) {
          throw new Error("registerAdBeaconInvoked function invoked more than once");
        }
        ps_report_result_response.interactionReportingUrls=eventUrlMap;
        ps_report_result_response.registerAdBeaconInvoked = true;
      }
      ps_signalsForWinner = reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals);
      try{
      if(buyerReportingMetadata.enableReportWinUrlGeneration){
        var buyerOrigin = buyerReportingMetadata.buyerOrigin
        var functionSuffix = buyerOrigin.replace(/[^a-zA-Z0-9 ]/g, "")
        var auctionSignals = auctionConfig.auctionSignals
        var buyerReportingSignals = sellerReportingSignals
        buyerReportingSignals.interestGroupName = buyerReportingMetadata.interestGroupName
        buyerReportingSignals.madeHighestScoringOtherBid = buyerReportingMetadata.madeHighestScoringOtherBid
        buyerReportingSignals.joinCount = buyerReportingMetadata.joinCount
        buyerReportingSignals.recency = buyerReportingMetadata.recency
        buyerReportingSignals.modelingSignals = buyerReportingMetadata.modelingSignals
        perBuyerSignals = buyerReportingMetadata.perBuyerSignals
        buyerReportingSignals.seller = buyerReportingMetadata.seller
        buyerReportingSignals.adCost = buyerReportingMetadata.adCost
        // Absence of interest group indicates that this is a protected app
        // signals ad.
        if (buyerReportingMetadata.enableProtectedAppSignals &&
            (buyerReportingSignals.interestGroupName === null ||
             buyerReportingSignals.interestGroupName.trim() === "")) {
          functionSuffix += "ProtectedAppSignals";
        }
        var reportWinFunction = "reportWinWrapper"+functionSuffix+"(auctionSignals, perBuyerSignals, ps_signalsForWinner, buyerReportingSignals,"+
                              "directFromSellerSignals, enable_logging, )"
        var reportWinResponse = eval(reportWinFunction)
        return {
          reportResultResponse: ps_report_result_response,
          sellerLogs: ps_logs,
          sellerErrors: ps_errors,
          sellerWarnings: ps_warns,
          reportWinResponse: reportWinResponse.response,
          buyerLogs: reportWinResponse.buyerLogs,
          buyerErrors: reportWinResponse.buyerErrors,
          buyerWarnings: reportWinResponse.buyerWarnings,
      }
      }
      } catch(ex){
        console.error(ex.message)
      }
      return {
        reportResultResponse: ps_report_result_response,
        sellerLogs: ps_logs,
        sellerErrors: ps_errors,
        sellerWarnings: ps_warns,
      }
    }

    // Handler method to call adTech provided reportWin method and wrap the
    // response with reportWin url and interaction reporting urls.
    function reportWinWrapperhttpbuyer1com(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, enable_logging, ) {
      var ps_report_win_response = {
        reportWinUrl : "",
        interactionReportingUrls : {},
        sendReportToInvoked : false,
        registerAdBeaconInvoked : false,
      }
      var ps_buyer_logs = [];
      var ps_buyer_error_logs = [];
      var ps_buyer_warning_logs = [];
      if(enable_logging){
        console.log = function(...args) {
          ps_buyer_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_buyer_error_logs.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_buyer_warning_logs.push(JSON.stringify(args))
        }
      }
      globalThis.sendReportTo = function sendReportTo(url){
        if(ps_report_win_response.sendReportToInvoked) {
          throw new Error("sendReportTo function invoked more than once");
        }
        ps_report_win_response.reportWinUrl = url;
        ps_report_win_response.sendReportToInvoked = true;
      }
      globalThis.registerAdBeacon = function registerAdBeacon(eventUrlMap){
        if(ps_report_win_response.registerAdBeaconInvoked) {
          throw new Error("registerAdBeaconInvoked function invoked more than once");
        }
        ps_report_win_response.interactionReportingUrls = eventUrlMap;
        ps_report_win_response.registerAdBeaconInvoked = true;
      }
      {
      reportWin = function(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals){
}
      }
      try{
      reportWin(auctionSignals, perBuyerSignals, signalsForWinner, buyerReportingSignals,
                              directFromSellerSignals, )
      } catch(ex){
        console.error(ex.message)
      }
      return {
        response: ps_report_win_response,
        buyerLogs: ps_buyer_logs,
        buyerErrors: ps_buyer_error_logs,
        buyerWarnings: ps_buyer_warning_logs
      }
    }

    function fibonacci(num) {
      if (num <= 1) return 1;
      return fibonacci(num - 1) + fibonacci(num - 2);
    }

    function scoreAd(ad_metadata, bid, auction_config, scoring_signals, device_signals, directFromSellerSignals){
      // Do a random amount of work to generate the score:
      const score = fibonacci(Math.floor(Math.random() * 10 + 1));
      console.log("Logging from ScoreAd")
      console.error("Logging error from ScoreAd")
      console.warn("Logging warn from ScoreAd")
      return {
        desirability: score,
        allow_component_auction: false
      }
    }
    function reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals){
        console.log("Logging from ReportResult");
        if(sellerReportingSignals.topLevelSeller === undefined || sellerReportingSignals.topLevelSeller.length === 0){
          sendReportTo("http://test.com")
        } else {
          sendReportTo("http://test.com&topLevelSeller="+sellerReportingSignals.topLevelSeller+"&componentSeller="+sellerReportingSignals.componentSeller)
        }
        registerAdBeacon({"clickEvent":"http://click.com"})
        return "testSignalsForWinner"
    }
)JS_CODE";

constexpr absl::string_view kExpectedCodeWithReportWinDisabled = R"JS_CODE(
    function scoreAdEntryFunction(adMetadata, bid, auctionConfig, trustedScoringSignals,
                                browserSignals, directFromSellerSignals, featureFlags){
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(featureFlags.enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }

      var forDebuggingOnly_auction_loss_url = undefined;
      var forDebuggingOnly_auction_win_url = undefined;
      const forDebuggingOnly = {};
      forDebuggingOnly.reportAdAuctionLoss = function(url){
        forDebuggingOnly_auction_loss_url = url;
      }
      forDebuggingOnly.reportAdAuctionWin = function(url){
        forDebuggingOnly_auction_win_url = url;
      }
      globalThis.forDebuggingOnly = forDebuggingOnly;

      var scoreAdResponse = {};
      try {
        scoreAdResponse = scoreAd(adMetadata, bid, auctionConfig,
              trustedScoringSignals, browserSignals, directFromSellerSignals);
      } catch({error, message}) {
          console.error("[Error: " + error + "; Message: " + message + "]");
      } finally {
        if( featureFlags.enable_debug_url_generation &&
              (forDebuggingOnly_auction_loss_url
                  || forDebuggingOnly_auction_win_url)) {
          scoreAdResponse.debugReportUrls = {
            auctionDebugLossUrl: forDebuggingOnly_auction_loss_url,
            auctionDebugWinUrl: forDebuggingOnly_auction_win_url
          }
        }
      }
      return {
        response: scoreAdResponse,
        logs: ps_logs,
        errors: ps_errors,
        warnings: ps_warns
      }
    }

    //Handler method to call adTech provided reportResult method and wrap the
    // response with reportResult url and interaction reporting urls.
    function reportingEntryFunction(auctionConfig, sellerReportingSignals, directFromSellerSignals, enable_logging, buyerReportingMetadata, ) {
    ps_signalsForWinner = ""
    var ps_report_result_response = {
        reportResultUrl : "",
        interactionReportingUrls : {},
        sendReportToInvoked : false,
        registerAdBeaconInvoked : false,
      }
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }
      globalThis.sendReportTo = function sendReportTo(url){
        if(ps_report_result_response.sendReportToInvoked) {
          throw new Error("sendReportTo function invoked more than once");
        }
        ps_report_result_response.reportResultUrl = url;
        ps_report_result_response.sendReportToInvoked = true;
      }
      globalThis.registerAdBeacon = function registerAdBeacon(eventUrlMap){
        if(ps_report_result_response.registerAdBeaconInvoked) {
          throw new Error("registerAdBeaconInvoked function invoked more than once");
        }
        ps_report_result_response.interactionReportingUrls=eventUrlMap;
        ps_report_result_response.registerAdBeaconInvoked = true;
      }
      ps_signalsForWinner = reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals);
      try{
      if(buyerReportingMetadata.enableReportWinUrlGeneration){
        var buyerOrigin = buyerReportingMetadata.buyerOrigin
        var functionSuffix = buyerOrigin.replace(/[^a-zA-Z0-9 ]/g, "")
        var auctionSignals = auctionConfig.auctionSignals
        var buyerReportingSignals = sellerReportingSignals
        buyerReportingSignals.interestGroupName = buyerReportingMetadata.interestGroupName
        buyerReportingSignals.madeHighestScoringOtherBid = buyerReportingMetadata.madeHighestScoringOtherBid
        buyerReportingSignals.joinCount = buyerReportingMetadata.joinCount
        buyerReportingSignals.recency = buyerReportingMetadata.recency
        buyerReportingSignals.modelingSignals = buyerReportingMetadata.modelingSignals
        perBuyerSignals = buyerReportingMetadata.perBuyerSignals
        buyerReportingSignals.seller = buyerReportingMetadata.seller
        buyerReportingSignals.adCost = buyerReportingMetadata.adCost
        // Absence of interest group indicates that this is a protected app
        // signals ad.
        if (buyerReportingMetadata.enableProtectedAppSignals &&
            (buyerReportingSignals.interestGroupName === null ||
             buyerReportingSignals.interestGroupName.trim() === "")) {
          functionSuffix += "ProtectedAppSignals";
        }
        var reportWinFunction = "reportWinWrapper"+functionSuffix+"(auctionSignals, perBuyerSignals, ps_signalsForWinner, buyerReportingSignals,"+
                              "directFromSellerSignals, enable_logging, )"
        var reportWinResponse = eval(reportWinFunction)
        return {
          reportResultResponse: ps_report_result_response,
          sellerLogs: ps_logs,
          sellerErrors: ps_errors,
          sellerWarnings: ps_warns,
          reportWinResponse: reportWinResponse.response,
          buyerLogs: reportWinResponse.buyerLogs,
          buyerErrors: reportWinResponse.buyerErrors,
          buyerWarnings: reportWinResponse.buyerWarnings,
      }
      }
      } catch(ex){
        console.error(ex.message)
      }
      return {
        reportResultResponse: ps_report_result_response,
        sellerLogs: ps_logs,
        sellerErrors: ps_errors,
        sellerWarnings: ps_warns,
      }
    }

    function fibonacci(num) {
      if (num <= 1) return 1;
      return fibonacci(num - 1) + fibonacci(num - 2);
    }

    function scoreAd(ad_metadata, bid, auction_config, scoring_signals, device_signals, directFromSellerSignals){
      // Do a random amount of work to generate the score:
      const score = fibonacci(Math.floor(Math.random() * 10 + 1));
      console.log("Logging from ScoreAd")
      console.error("Logging error from ScoreAd")
      console.warn("Logging warn from ScoreAd")
      return {
        desirability: score,
        allow_component_auction: false
      }
    }
    function reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals){
        console.log("Logging from ReportResult");
        if(sellerReportingSignals.topLevelSeller === undefined || sellerReportingSignals.topLevelSeller.length === 0){
          sendReportTo("http://test.com")
        } else {
          sendReportTo("http://test.com&topLevelSeller="+sellerReportingSignals.topLevelSeller+"&componentSeller="+sellerReportingSignals.componentSeller)
        }
        registerAdBeacon({"clickEvent":"http://click.com"})
        return "testSignalsForWinner"
    }
)JS_CODE";

constexpr absl::string_view kExpectedCodeWithReportingDisabled = R"JS_CODE(
    function scoreAdEntryFunction(adMetadata, bid, auctionConfig, trustedScoringSignals,
                                browserSignals, directFromSellerSignals, featureFlags){
      var ps_logs = [];
      var ps_errors = [];
      var ps_warns = [];
      if(featureFlags.enable_logging){
        console.log = function(...args) {
          ps_logs.push(JSON.stringify(args))
        }
        console.error = function(...args) {
          ps_errors.push(JSON.stringify(args))
        }
        console.warn = function(...args) {
          ps_warns.push(JSON.stringify(args))
        }
      }

      var forDebuggingOnly_auction_loss_url = undefined;
      var forDebuggingOnly_auction_win_url = undefined;
      const forDebuggingOnly = {};
      forDebuggingOnly.reportAdAuctionLoss = function(url){
        forDebuggingOnly_auction_loss_url = url;
      }
      forDebuggingOnly.reportAdAuctionWin = function(url){
        forDebuggingOnly_auction_win_url = url;
      }
      globalThis.forDebuggingOnly = forDebuggingOnly;

      var scoreAdResponse = {};
      try {
        scoreAdResponse = scoreAd(adMetadata, bid, auctionConfig,
              trustedScoringSignals, browserSignals, directFromSellerSignals);
      } catch({error, message}) {
          console.error("[Error: " + error + "; Message: " + message + "]");
      } finally {
        if( featureFlags.enable_debug_url_generation &&
              (forDebuggingOnly_auction_loss_url
                  || forDebuggingOnly_auction_win_url)) {
          scoreAdResponse.debugReportUrls = {
            auctionDebugLossUrl: forDebuggingOnly_auction_loss_url,
            auctionDebugWinUrl: forDebuggingOnly_auction_win_url
          }
        }
      }
      return {
        response: scoreAdResponse,
        logs: ps_logs,
        errors: ps_errors,
        warnings: ps_warns
      }
    }

    function fibonacci(num) {
      if (num <= 1) return 1;
      return fibonacci(num - 1) + fibonacci(num - 2);
    }

    function scoreAd(ad_metadata, bid, auction_config, scoring_signals, device_signals, directFromSellerSignals){
      // Do a random amount of work to generate the score:
      const score = fibonacci(Math.floor(Math.random() * 10 + 1));
      console.log("Logging from ScoreAd")
      console.error("Logging error from ScoreAd")
      console.warn("Logging warn from ScoreAd")
      return {
        desirability: score,
        allow_component_auction: false
      }
    }
    function reportResult(auctionConfig, sellerReportingSignals, directFromSellerSignals){
        console.log("Logging from ReportResult");
        if(sellerReportingSignals.topLevelSeller === undefined || sellerReportingSignals.topLevelSeller.length === 0){
          sendReportTo("http://test.com")
        } else {
          sendReportTo("http://test.com&topLevelSeller="+sellerReportingSignals.topLevelSeller+"&componentSeller="+sellerReportingSignals.componentSeller)
        }
        registerAdBeacon({"clickEvent":"http://click.com"})
        return "testSignalsForWinner"
    }
)JS_CODE";
}  // namespace privacy_sandbox::bidding_auction_servers
#endif  // FLEDGE_SERVICES_SELLER_CODE_WRAPPER_TEST_CONSTANTS_H_
