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
var monkeysphere = {

  // MONKEYSPHERE STATES:
  // ERROR      : there was a monkeysphere processing error
  // NEUTRAL    :  neutral on this site (no icon)
  // INPROGRESS : in progress (querying agent)
  // VALID      : processed and validated
  // NOTVALID   : processed and not validated

  // agent URL from environment variable
  // "http://localhost:8901" <-- NO TRAILING SLASH
  agent_socket: [],

  // default socket
  // FIXME: should be configurable via prefs.js
  default_socket: "http://localhost:8901",

  // override service class
  // http://www.oxymoronical.com/experiments/xpcomref/applications/Firefox/3.5/interfaces/nsICertOverrideService
  override: Components.classes["@mozilla.org/security/certoverride;1"].getService(Components.interfaces.nsICertOverrideService),

////////////////////////////////////////////////////////////
// LOG FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  log: function(line) {
    var message = "monkeysphere: " + line;

    try {
      dump(message + "\n");
      try {
        // this line works in extensions
        Firebug.Console.log(message);
      } catch(e) {
        // ignore, this will blow up if Firebug is not installed
      }
      try {
        console.log(message); // this line works in HTML files
      } catch(e) {
        // ignore, this will blow up if Firebug is not installed
      }
    } catch(e) {
      alert(e);
    }
  },

  dump: function(obj) {
    for (var key in obj) {
      monkeysphere.log("dump: " + key + " = " + obj[key]);
    }
  },

////////////////////////////////////////////////////////////
// INITIALIZATION
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // initialization function
  init: function() {
    monkeysphere.log("---- begin initialization ----");

    // get localization messages
    monkeysphere.messages = document.getElementById("message_strings");

    // get the agent URL from the environment
    // https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsIEnvironment
    monkeysphere.agent_socket = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("MONKEYSPHERE_VALIDATION_AGENT_SOCKET");
    // return error if agent URL not set
    if(!monkeysphere.agent_socket) {
      var message = "MONKEYSPHERE_VALIDATION_AGENT_SOCKET environment variable not set.  Using default of " + monkeysphere.default_socket;
      alert(message);
      monkeysphere.agent_socket = monkeysphere.default_socket;
    }
    // replace trailing slashes
    monkeysphere.agent_socket = monkeysphere.agent_socket.replace(/\/*$/, '');
    monkeysphere.log("agent socket: " + monkeysphere.agent_socket);

    // create event listeners
    monkeysphere.log("creating listeners...");
    gBrowser.addProgressListener(monkeysphere.progressListener);
    gBrowser.addTabsProgressListener(monkeysphere.tabProgressListener);

    monkeysphere.log("---- initialization complete ----");
  },

////////////////////////////////////////////////////////////
// LISTENERS
////////////////////////////////////////////////////////////

  // https://developer.mozilla.org/en/nsIWebProgressListener
  progressListener: {
    onLocationChange: function(aWebProgress, aRequest, aLocation) {
      monkeysphere.log("++++ PL location change: " + aLocation.prePath);
      monkeysphere.updateDisplay();
    },

    onProgressChange: function() {},
    onSecurityChange: function() {},
    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {},
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {}
  },

  // https://developer.mozilla.org/en/Listening_to_events_on_all_tabs
  tabProgressListener: {
    onSecurityChange: function(aBrowser, aWebProgress, aRequest, aState) {
      monkeysphere.log("++++ tabPL security change: ");
      monkeysphere.checkSite(aBrowser, aState);
    },

    onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation) {
      //monkeysphere.log("++++ tabPL location change: " + aLocation.prePath);
    },
    onProgressChange: function(aBrowser, awebProgress, aRequest, curSelfProgress, maxSelfProgress, curTotalProgress, maxTotalProgress) {
      //monkeysphere.log("++++ tabPL progress change: " + curSelfProgress);
    },
    onStateChange: function(aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
      monkeysphere.log("++++ tabPL state change: " + aRequest);
      monkeysphere.updateDisplay();
    },
    onStatusChange: function(aBrowser, aWebProgress, aRequest, aStatus, aMessage) {
      //monkeysphere.log("++++ tabPL status change: " + aRequest);
    }
  },

////////////////////////////////////////////////////////////
// SITE URI CHECK FUNCTION
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // check uri is relevant to monkeysphere
  isRelevantURI: function(uri) {
    ////////////////////////////////////////
    // check host
    try {
      var host = uri.host;
    } catch(e) {
      monkeysphere.log("host data empty.");
      return null;
    }

    ////////////////////////////////////////
    // check scheme
    try {
      var scheme = uri.scheme;
    } catch(e) {
      monkeysphere.log("scheme data empty.");
      return null;
    }

    monkeysphere.log("url: " + uri.asciiSpec);

    ////////////////////////////////////////
    // check if scheme is https
    if(scheme != "https") {
      monkeysphere.log("scheme not https.");
      return null;
    }

    // if uri is relevant for monkeysphere return true
    return true;
  },

////////////////////////////////////////////////////////////
// MAIN SITE CHECK FUNCTION
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // check site monkeysphere status
  checkSite: function(browser, state) {
    monkeysphere.log("check site:");

    var uri = browser.currentURI;

    // if uri not relevant, return
    if(!monkeysphere.isRelevantURI(uri)) {
      monkeysphere.setStatus(browser, 'NEUTRAL');
      return;
    }

    ////////////////////////////////////////
    // check browser state
    monkeysphere.log("checking security state: " + state);
    // if site secure...
    if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
      monkeysphere.log("  site state SECURE.");

      // if a monkeysphere-generated cert override is being used by this connection, then we should be setting the status from the override
      var apd = monkeysphere.createAgentPostData(browser, browser.securityUI.SSLStatus.serverCert);
      var response = monkeysphere.cache.get(apd);
      if ( typeof response === 'undefined' ) {
        monkeysphere.setStatus(browser, 'NEUTRAL');
      } else {
        monkeysphere.setStatus(browser, 'VALID', response.message);
      }
      return;

    // if site insecure continue
    } else if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE) {
      monkeysphere.log("  site state INSECURE");

    // else if unknown state continue
    } else {
      monkeysphere.log("  site state is unknown");
    }

    ////////////////////////////////////////
    // get site certificate
    monkeysphere.log("retrieving site certificate:");
    var cert = monkeysphere.getCertificate(uri);

    ////////////////////////////////////////
    // finally go ahead and query the agent
    monkeysphere.log("querying agent...");
    monkeysphere.queryAgent(browser, cert);
  },

  //////////////////////////////////////////////////////////
  // set site monkeysphere status
  setStatus: function(browser, state, message) {
    if ( typeof message === 'undefined' ) {
      var key = "status" + state;
      message = monkeysphere.messages.getString(key);
    }
    monkeysphere.log("set browser status: " + state + ', ' + message);
    browser.monkeysphere = { state: state, message: message };
  },

  //////////////////////////////////////////////////////////
  // clear site monkeysphere status for browser
  clearStatus: function(browser) {
    monkeysphere.log("clear browser status");
    delete browser.monkeysphere;
  },

////////////////////////////////////////////////////////////
// UPDATE DISPLAY
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // update the display for the currently visible browser
  updateDisplay: function() {
    monkeysphere.log("update display:");

    var browser = gBrowser.selectedBrowser;
    var panel = document.getElementById("monkeysphere-status");
    var icon = document.getElementById("monkeysphere-status-image");

    // the following happens when called from a dialog
    if(!panel || !icon) {
      monkeysphere.log("  panel/icon not available; falling back to window.opener");
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

    monkeysphere.log("  state: " + state);
    switch(state){
      case 'INPROGRESS':
        icon.setAttribute("src", "chrome://monkeysphere/content/progress.gif");
        panel.hidden = false;
        break;
      case 'VALID':
        icon.setAttribute("src", "chrome://monkeysphere/content/good.png");
        panel.hidden = false;
        break;
      case 'NOTVALID':
        icon.setAttribute("src", "chrome://monkeysphere/content/bad.png");
        panel.hidden = false;
        break;
      case 'NEUTRAL':
        icon.setAttribute("src", "");
        panel.hidden = true;
        break;
      case 'ERROR':
        icon.setAttribute("src", "chrome://monkeysphere/content/error.png");
        panel.hidden = false;
        break;
    }

    monkeysphere.log("  message: " + message);
    panel.setAttribute("tooltiptext", message);
  },

////////////////////////////////////////////////////////////
// AGENT QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  createAgentPostData: function(browser, cert) {
    var uri = browser.currentURI;
    // get certificate info
    var cert_length = {};
    var dummy = {};
    var cert_data = cert.getRawDER(cert_length, dummy);

    // "agent post data"
    var apd = {
      data: {
        context: uri.scheme,
        peer: uri.hostPort,
        pkc: {
          type: "x509der",
          data: cert_data
        },
      },
      toJSON: function() {
        return JSON.stringify(this.data);
      },
      toCacheLabel: function() {
        return this.data.context + '|' + this.data.peer + '|' + this.data.pkc.type + '|' + this.data.pkc.data;
      },
      log: function() {
        monkeysphere.log("agent post data:");
        monkeysphere.log("  context: " + this.data.context);
        monkeysphere.log("  peer: " + this.data.peer);
        monkeysphere.log("  pkc.type: " + this.data.pkc.type);
        //monkeysphere.log("  pkc.data: " + this.data.pkc.data); // this can be big
        //monkeysphere.log("  JSON: " + this.toJSON());
      }
    };

    return apd;
  },

  //////////////////////////////////////////////////////////
  // query the validation agent
  queryAgent: function(browser, cert) {
    monkeysphere.log("#### querying validation agent ####");

    monkeysphere.log("agent_socket: " + monkeysphere.agent_socket);

    // make the client request object
    var client = new XMLHttpRequest();

    // make JSON query string
    client.apd = monkeysphere.createAgentPostData(browser, cert);
    client.apd.log();
    var query = client.apd.toJSON();

    var request_url = monkeysphere.agent_socket + "/reviewcert";
    monkeysphere.log("creating http request to " + request_url);
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

    monkeysphere.log("sending query...");
    client.send(query);
    monkeysphere.log("query sent");
    monkeysphere.setStatus(browser, 'INPROGRESS');
  },

  //////////////////////////////////////////////////////////
  // when the XMLHttpRequest to the agent state changes
  onAgentStateChange: function(client, browser, cert) {
    monkeysphere.log("agent query state change: " + client.readyState);
    monkeysphere.log("  status: " + client.status);
    monkeysphere.log("  response: " + client.responseText);

    if (client.readyState == 4) {
      if (client.status == 200) {

        var response = JSON.parse(client.responseText);

        if (response.valid) {

          monkeysphere.cache.set(client.apd, response);

          // VALID!
          monkeysphere.log("SITE VERIFIED!");
          monkeysphere.securityOverride(browser.currentURI, cert);
          monkeysphere.setStatus(browser, 'VALID', response.message);

          // reload page
          monkeysphere.log("reloading browser...");
          browser.webNavigation.reload(nsIWebNavigation.LOAD_FLAGS_NONE);

        } else {

          // NOT VALID
          monkeysphere.log("site not verified.");
          monkeysphere.setStatus(browser, 'NOTVALID', response.message);

        }
      } else {
        monkeysphere.log("validation agent did not respond.");
        //alert(monkeysphere.messages.getString("agentError"));
        monkeysphere.setStatus(browser, 'ERROR', monkeysphere.messages.getString('noResponseFromAgent'));
      }

      // update the current display, so that if we're looking at the
      // browser being processed, the result will be immediately displayed
      monkeysphere.updateDisplay();
    }
  },

////////////////////////////////////////////////////////////
// OVERRIDE FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // get current validity override status
  checkOverrideStatus: function(uri) {
    // the status return is a bool, true for override set
    var status;
    var aHashAlg = {};
    var aFingerprint = {};
    var aOverrideBits = {};
    var aIsTemporary = {};
    status = monkeysphere.override.getValidityOverride(uri.asciiHost, uri.port,
                                                       aHashAlg,
                                                       aFingerprint,
                                                       aOverrideBits,
                                                       aIsTemporary);
    monkeysphere.log("current override status: " + status);
    return status;
  },

  //////////////////////////////////////////////////////////
  // browser security override function
  securityOverride: function(uri, cert) {
    monkeysphere.log("**** CERT SECURITY OVERRIDE ****");

    var SSLStatus = monkeysphere.getInvalidCertSSLStatus(uri);
    var overrideBits = 0;

    // set override bits
    // FIXME: should this just be for all flags by default?
    if(SSLStatus.isUntrusted) {
      monkeysphere.log("flag: ERROR_UNTRUSTED");
      overrideBits |= monkeysphere.override.ERROR_UNTRUSTED;
    }
    if(SSLStatus.isDomainMismatch) {
      monkeysphere.log("flag: ERROR_MISMATCH");
      overrideBits |= monkeysphere.override.ERROR_MISMATCH;
    }
    if(SSLStatus.isNotValidAtThisTime) {
      monkeysphere.log("flag: ERROR_TIME");
      overrideBits |= monkeysphere.override.ERROR_TIME;
    }

    monkeysphere.log("overrideBits: " + overrideBits);

    monkeysphere.log("set cert override: " + uri.asciiHost + ":" + uri.port);
    monkeysphere.override.rememberValidityOverride(uri.asciiHost, uri.port,
                                                   cert,
                                                   overrideBits,
                                                   true);

    monkeysphere.log("**** CERT OVERRIDE SET ****");
  },

  //////////////////////////////////////////////////////////
  // clear an override
  clearOverride: function(uri) {
    monkeysphere.log("clear cert override: " + uri.asciiHost + ":" + uri.port);
    monkeysphere.override.clearValidityOverride(uri.asciiHost, uri.port);
  },

////////////////////////////////////////////////////////////
// CACHE OBJECT
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // cache object to store and retrieve data about monkeysphere status for sites
  // uses string of apd as key, and agent response as data
  cache: (function() {
    var responses = {};
    return {
      set: function(apd, agentResponse) {
        monkeysphere.log("set cache:");
        apd.log();
        responses[apd.toCacheLabel()] = agentResponse;
      },
      get: function(apd) {
        return responses[apd.toCacheLabel()];
      },
      clear: function(apd) {
        monkeysphere.log("clear cache:");
        apd.log();
        delete responses[apd.toCacheLabel()];
      }
    };
  })(),

////////////////////////////////////////////////////////////
// CERT FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // FWIW, aWebProgress listener has:
  // securityUI = [xpconnect wrapped (nsISupports, nsISecureBrowserUI, nsISSLStatusProvider)]
  // but i don't think it can be used because it doesn't hold invalid cert info
  // FIXME: is there a better way to get the cert for the actual current connection?
  getCertificate: function(uri) {
    try {
      var cert = monkeysphere.getInvalidCertSSLStatus(uri).QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
      monkeysphere.printCertInfo(cert);
      return cert;
    } catch(e) {
      return null;
    }
  },

  //////////////////////////////////////////////////////////
  // gets current ssl status info
  // http://www.oxymoronical.com/experiments/apidocs/interface/nsIRecentBadCertsService
  getInvalidCertSSLStatus: function(uri) {
    var recentCertsService =
      Components.classes["@mozilla.org/security/recentbadcerts;1"].getService(Components.interfaces.nsIRecentBadCertsService);
    if (!recentCertsService)
      return null;

    var port = uri.port;
    if(port == -1)
      port = 443;
    var hostWithPort = uri.host + ":" + port;

    var SSLStatus = recentCertsService.getRecentBadCert(hostWithPort);
    if (!SSLStatus)
      return null;

    return SSLStatus;
  },

  //////////////////////////////////////////////////////////
  // Print SSL certificate details
  // https://developer.mozilla.org/En/How_to_check_the_security_state_of_an_XMLHTTPRequest_over_SSL
  printCertInfo: function(cert) {
    const Ci = Components.interfaces;

    monkeysphere.log("certificate:");
    switch (cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer)) {
    case Ci.nsIX509Cert.VERIFIED_OK:
      monkeysphere.log("\tSSL status: OK");
      break;
    case Ci.nsIX509Cert.NOT_VERIFIED_UNKNOWN:
      monkeysphere.log("\tSSL status: not verfied/unknown");
      break;
    case Ci.nsIX509Cert.CERT_REVOKED:
      monkeysphere.log("\tSSL status: revoked");
      break;
    case Ci.nsIX509Cert.CERT_EXPIRED:
      monkeysphere.log("\tSSL status: expired");
      break;
    case Ci.nsIX509Cert.CERT_NOT_TRUSTED:
      monkeysphere.log("\tSSL status: not trusted");
      break;
    case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED:
      monkeysphere.log("\tSSL status: issuer not trusted");
      break;
    case Ci.nsIX509Cert.ISSUER_UNKNOWN:
      monkeysphere.log("\tSSL status: issuer unknown");
      break;
    case Ci.nsIX509Cert.INVALID_CA:
      monkeysphere.log("\tSSL status: invalid CA");
      break;
    default:
      monkeysphere.log("\tSSL status: unexpected failure");
      break;
    }
    monkeysphere.log("\tCommon Name: " + cert.commonName);
    monkeysphere.log("\tOrganisation: " + cert.organization);
    monkeysphere.log("\tIssuer: " + cert.issuerOrganization);
    monkeysphere.log("\tSHA1 fingerprint: " + cert.sha1Fingerprint);

    var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
    monkeysphere.log("\tValid from: " + validity.notBeforeGMT);
    monkeysphere.log("\tValid until: " + validity.notAfterGMT);
  },

////////////////////////////////////////////////////////////
// FAVICON FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  getFaviconText: function() {
    return document.getElementById("identity-box").tooltipText;
  },

  //////////////////////////////////////////////////////////
  //Sets the tooltip and the text of the favicon popup on https sites
  setFaviconText: function(str) {
    document.getElementById("identity-box").tooltipText = str;
  },

  contextMenuFunctions: {
    clearSite: function() {
      monkeysphere.log("--- clear site ---");
      var browser = gBrowser.selectedBrowser;
      var uri = browser.currentURI;
      monkeysphere.clearOverride(uri);
      monkeysphere.clearStatus(browser);
      try {
        var apd = monkeysphere.createAgentPostData(browser, browser.securityUI.SSLStatus.serverCert);
        monkeysphere.cache.clear(apd);
      } catch(e) {
        monkeysphere.log("no valid cert for site found");
      }
      monkeysphere.updateDisplay();
    },
    certs: function() {
      openDialog("chrome://pippki/content/certManager.xul", "Certificate Manager");
    },
    help: function() {
      gBrowser.loadOneTab("chrome://monkeysphere/locale/help.html",
      null, null, null, false);
    }
  }
};
