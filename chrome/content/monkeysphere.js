// Monkeysphere XUL extension
// Copyright © 2010 Jameson Rollins <jrollins@finestructure.net>,
//                  Daniel Kahn Gillmor <dkg@fifthhorseman.net>,
//                  mike castleman <m@mlcastle.net>,
//                  Matthew James Goins <mjgoins@openflows.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Monkeysphere global namespace
var monkeysphere = (function() {

  // MONKEYSPHERE STATES:
  // ERROR      : there was a monkeysphere processing error
  // NEUTRAL    :  neutral on this site (no icon)
  // INPROGRESS : in progress (querying agent)
  // VALID      : processed and validated
  // NOTVALID   : processed and not validated

////////////////////////////////////////////////////////////
// MAIN SITE CHECK FUNCTION
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // check site monkeysphere status
  var checkSite = function(browser, state) {
    ms.log("%%%% checking site %%%%");

    var uri = browser.currentURI;

    // if uri not relevant, return
    // FIXME: should we be doing this check here?  this is triggered by a security state change.  Does it matter if the url is not https?
    if(!ms.isRelevantURI(uri)) {
      ms.setStatus(browser, 'NEUTRAL');
      return;
    }

    ////////////////////////////////////////
    // check browser state
    // if site secure...
    if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
      ms.log("security state: SECURE.");

      // if a monkeysphere-generated cert override is being used by this connection, then we should be setting the status from the override
      var cert = browser.securityUI.SSLStatus.serverCert;
      var apd = ms.createAgentPostData(uri, cert);
      var response = ms.overrides.response(apd);

      if ( typeof response === 'undefined' ) {
        ms.setStatus(browser, 'NEUTRAL');
      } else {
        ms.setStatus(browser, 'VALID', response.message);
      }
      return;

    } else if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN) {
      ms.log("security state: BROKEN");

      // if a monkeysphere-generated cert override is being used by this connection, then we should be setting the status from the override
      try {
        var cert = browser.securityUI.SSLStatus.serverCert;
      } catch(e) {
        ms.log("no cert found");
        return;
      }
      var apd = ms.createAgentPostData(uri, cert);
      var response = ms.overrides.response(apd);

      if ( typeof response === 'undefined' ) {
        ms.setStatus(browser, 'NEUTRAL');
      } else {
        // modify the message to indicate that it's only partially validated
        var newmessage = response.message + ' [Warning: contains non-monkeysphere validated content]';
        ms.setStatus(browser, 'BROKEN', newmessage);
      }
      return;

    // if site insecure continue
    } else if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE) {
      ms.log("security state: INSECURE");

    // else if unknown state continue
    } else {
      ms.log("security state: UNKNOWN");
    }

    ////////////////////////////////////////
    // get site certificate
    ms.log("retrieving site certificate...");
    var cert = ms.getInvalidCert(uri);

    ////////////////////////////////////////
    // finally go ahead and query the agent
    ms.log("querying agent...");
    queryAgent(browser, cert);
  };

////////////////////////////////////////////////////////////
// AGENT QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // query the validation agent
  var queryAgent = function(browser, cert) {
    ms.log("#### querying validation agent ####");
    var socket = ms.agent_socket();

    var uri = browser.currentURI;

    // make the client request object
    var client = new XMLHttpRequest();

    // make JSON query string
    client.apd = ms.createAgentPostData(uri, cert);
    client.apd.log();
    var query = client.apd.toJSON();

    var request_url = socket + "/reviewcert";
    ms.log("creating http request to " + request_url);
    client.open("POST", request_url, true);

    // set headers
    client.setRequestHeader("Content-Type", "application/json");
    client.setRequestHeader("Content-Length", query.length);
    client.setRequestHeader("Connection", "close");
    client.setRequestHeader("Accept", "application/json");

    // setup the state change function
    client.onreadystatechange = function() {
      monkeysphere.onAgentStateChange(client, browser, cert);
    };

    ms.log("sending query...");
    client.send(query);
    ms.log("query sent");
    ms.setStatus(browser, 'INPROGRESS', monkeysphere.messages.getString('statusINPROGRESS'));
  };

////////////////////////////////////////////////////////////
// UPDATE DISPLAY
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // update the display for the currently visible browser
  var updateDisplay = function() {
    ms.log("update display:");

    var browser = gBrowser.selectedBrowser;
    var panel = document.getElementById("monkeysphere-status");
    var icon = document.getElementById("monkeysphere-status-image");

    // the following happens when called from a dialog
    if(!panel || !icon) {
      ms.log("  panel/icon not available; falling back to window.opener");
      panel = window.opener.document.getElementById("monkeysphere-status");
      icon = window.opener.document.getElementById("monkeysphere-status-image");
    }

    // set state neutral by default
    var state = 'NEUTRAL';
    var message = "";

    // set from the browser monkeysphere state object if available
    if( typeof browser.monkeysphere !== "undefined" ) {
      state = browser.monkeysphere.state;
      message = browser.monkeysphere.message;
    }

    ms.log("  state: " + state);
    switch(state){
      case 'INPROGRESS':
        icon.setAttribute("src", "chrome://monkeysphere/content/progress.gif");
        panel.hidden = false;
        document.getElementById("monkeysphere-status-clearSite").hidden = true;
        document.getElementById("monkeysphere-status-showCache").hidden = true;
        break;
      case 'VALID':
        icon.setAttribute("src", "chrome://monkeysphere/content/monkey.png");
        panel.hidden = false;
        document.getElementById("monkeysphere-status-clearSite").hidden = false;
        document.getElementById("monkeysphere-status-showCache").hidden = false;
        break;
      case 'BROKEN':
        icon.setAttribute("src", "chrome://monkeysphere/content/broken.png");
        panel.hidden = false;
        document.getElementById("monkeysphere-status-clearSite").hidden = false;
        document.getElementById("monkeysphere-status-showCache").hidden = false;
        break;
      case 'CLEARED':
        icon.setAttribute("src", "chrome://monkeysphere/content/monkey.png");
        panel.hidden = false;
        document.getElementById("monkeysphere-status-clearSite").hidden = true;
        document.getElementById("monkeysphere-status-showCache").hidden = true;
        break;
      case 'NOTVALID':
        icon.setAttribute("src", "chrome://monkeysphere/content/bad.png");
        panel.hidden = false;
        document.getElementById("monkeysphere-status-clearSite").hidden = true;
        document.getElementById("monkeysphere-status-showCache").hidden = true;
        break;
      case 'NEUTRAL':
        icon.setAttribute("src", "");
        panel.hidden = true;
        break;
      case 'ERROR':
        icon.setAttribute("src", "chrome://monkeysphere/content/error.png");
        panel.hidden = false;
        document.getElementById("monkeysphere-status-clearSite").hidden = true;
        document.getElementById("monkeysphere-status-showCache").hidden = true;
        break;
    }

    if(state != 'NEUTRAL') {
      ms.log("  message: " + message);
    }
    panel.setAttribute("tooltiptext", message);
  };

  var ms = {};
  Components.utils.import("resource://monkeysphere/monkeysphere.jsm", ms);

////////////////////////////////////////////////////////////
// EXTERNAL INTERFACE
////////////////////////////////////////////////////////////

  return {

    ////////////////////////////////////////////////////////
    // INITIALIZATION
    ////////////////////////////////////////////////////////

    init: function() {
      ms.log("---- begin initialization ----");

      // get localization messages
      monkeysphere.messages = document.getElementById("message_strings");

      // create event listeners
      ms.log("creating listeners...");
      gBrowser.addProgressListener(monkeysphere.progressListener);
      gBrowser.addTabsProgressListener(monkeysphere.tabProgressListener);

      ms.log("---- initialization complete ----");
    },

    ////////////////////////////////////////////////////////
    // LISTENERS
    ////////////////////////////////////////////////////////

    // https://developer.mozilla.org/en/nsIWebProgressListener
    progressListener: {
      onLocationChange: function(aWebProgress, aRequest, aLocation) {
        ms.log("++++ PL location change ++++");
        updateDisplay();
      },
      onProgressChange: function(aWebProgress, aRequest, aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress, aMaxTotalProgress) {},
      onSecurityChange: function(aWebProgress, aRequest, aState) {},
      onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {},
      onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {}
    },

    // https://developer.mozilla.org/en/Listening_to_events_on_all_tabs
    tabProgressListener: {
      onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation) {},
      onProgressChange: function(aBrowser, awebProgress, aRequest, curSelfProgress, maxSelfProgress, curTotalProgress, maxTotalProgress) {},
      onSecurityChange: function(aBrowser, aWebProgress, aRequest, aState) {
        ms.log("++++ tabPL security change: " + aState + " ++++");
        checkSite(aBrowser, aState);
        updateDisplay();
      },
      onStateChange: function(aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
        ms.log("++++ tabPL state change: " + aStateFlags + " ++++");
        updateDisplay();
      },
      onStatusChange: function(aBrowser, aWebProgress, aRequest, aStatus, aMessage) {}
    },

    ////////////////////////////////////////////////////////
    // when the XMLHttpRequest to the agent state changes
    onAgentStateChange: function(client, browser, cert) {
      ms.log("agent query state change: " + client.readyState);
      ms.log("  status: " + client.status);
      ms.log("  response: " + client.responseText);

      if (client.readyState == 4) {
        if (client.status == 200) {

          var response = JSON.parse(client.responseText);

          if (response.valid) {

            // VALID!
            ms.log("SITE VERIFIED!");
            ms.overrides.set(client.apd, response);
            ms.setStatus(browser, 'VALID', response.message);

            // reload page
            ms.log("reloading browser...");
            browser.webNavigation.reload(nsIWebNavigation.LOAD_FLAGS_NONE);

          } else {

            // NOT VALID
            ms.log("site not verified.");
            ms.setStatus(browser, 'NOTVALID', response.message);

          }
        } else {
          ms.log("validation agent did not respond.");
          ms.setStatus(browser, 'ERROR', monkeysphere.messages.getString('noResponseFromAgent'));
        }

        // update the current display, so that if we're looking at the
        // browser being processed, the result will be immediately displayed
        updateDisplay();
      }
    },

    ////////////////////////////////////////////////////////
    // CONTEXT MENU FUNCTIONS
    ////////////////////////////////////////////////////////

    contextMenuFunctions: {

      clearSite: function() {
        ms.log("context menu function: clearSite");
        var browser = gBrowser.selectedBrowser;
        var uri = browser.currentURI;
        try {
          var cert = browser.securityUI.SSLStatus.serverCert;
        } catch(e) {
          ms.log("no valid cert found?  probably already cleared?");
          return;
        }
        var apd = ms.createAgentPostData(uri, cert);
        apd.log();
        ms.overrides.clear(apd);
        if(ms.overrides.certStatus(apd)) {
          ms.log("**** WARNING: override cert not cleared ****");
          alert('Monkeysphere error: override cert not cleared!');
        }
        var newstate = "CLEARED";
        var newmessage = browser.monkeysphere.message + ' [NO LONGER CACHED]';
        ms.setStatus(browser, newstate, newmessage);
        updateDisplay();
      },

      showCache: function() {
        ms.log("context menu function: showCache");
        var browser = gBrowser.selectedBrowser;
        var uri = browser.currentURI;
        try {
          var cert = browser.securityUI.SSLStatus.serverCert;
        } catch(e) {
          ms.log("no valid cert found?  probably already cleared?");
          return;
        }
        var apd = ms.createAgentPostData(uri, cert);

        var string = "Monkeysphere cache information:\n\n";
        string += "context: " + apd.data.context + "\n";
        string += "peer: " + apd.data.peer + "\n";
        string += "pkc type: " + apd.data.pkc.type + "\n";
        string += "agent response: " + ms.overrides.response(apd).message + "\n";

        alert(string);
      },

      certs: function() {
        openDialog("chrome://pippki/content/certManager.xul", "Certificate Manager");
      },

      help: function() {
        ms.log("context menu function: help");
        gBrowser.loadOneTab("chrome://monkeysphere/locale/help.html",
        null, null, null, false);
      }
    }
  };
})();
