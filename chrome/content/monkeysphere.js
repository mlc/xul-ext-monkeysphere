// Monkeysphere XUL extension
// Copyright © 2010 Jameson Rollins <jrollins@finestructure.net>,
//                  Daniel Kahn Gillmor <dkg@fifthhorseman.net>
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

  states: {
    ERROR:   -1, // there was a monkeysphere processing error
    NEUTRAL:  0, // neutral on this site (no icon)
    PROGRESS: 1, // in progress (querying agent)
    VALID:    2, // processed and validated
    INVALID:  3  // processed and not validated
  },

  // override service class
  // http://www.oxymoronical.com/experiments/xpcomref/applications/Firefox/3.5/interfaces/nsICertOverrideService
  override: Components.classes["@mozilla.org/security/certoverride;1"].getService(Components.interfaces.nsICertOverrideService),

  uid: function(uri) {
    return uri.scheme + '://' + uri.host;
  },

////////////////////////////////////////////////////////////
// LOG FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
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
      var value = obj[key];
      monkeysphere.log("dump: " + key + " : " + value);
    }
  },

////////////////////////////////////////////////////////////
// INITIALIZATION
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // initialization function
  init: function() {
    monkeysphere.log("---- begin initialization ----");
    monkeysphere.setStatus();
    monkeysphere.messages = document.getElementById("message_strings");
    monkeysphere.log("creating listener.");
    getBrowser().addProgressListener(monkeysphere.listener,
				     Components.interfaces.nsIWebProgress.NOTIFY_ALL);
    // FIXME: do we need this?  what is it for?
    //setTimeout(function (){ monkeysphere.requeryAllTabs(gBrowser); }, 4000);
    monkeysphere.log("---- initialization complete ----");
  },

  ////////////////////////////////////////////////////////////
  // FIXME: what is this functions for?  should we be using it?
  requeryAllTabs: function(b) {
    var num = b.browsers.length;
    for (var i = 0; i < num; i++) {
      var browser = b.getBrowserAtIndex(i);
      monkeysphere.updateStatus(browser);
    }
  },

////////////////////////////////////////////////////////////
// EVENT LISTENER
////////////////////////////////////////////////////////////

  // https://developer.mozilla.org/en/nsIWebProgressListener
  listener: {
    onLocationChange: function(aWebProgress, aRequest, aLocation) {
      monkeysphere.log("++++ location change: " + aLocation + " ++++");
      return;
      try {
	monkeysphere.updateStatus(aWebProgress, aRequest, aLocation);
      } catch(err) {
	monkeysphere.log("listener: location change: " + err);
	monkeysphere.setStatus(monkeysphere.states.ERROR,
			       monkeysphere.messages.getFormattedString("internalError", [err]));
      }
    },

    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
      monkeysphere.log("++++ state change: " + aStateFlags + " ++++");
      return;
    },

    onSecurityChange: function(aWebProgress, aRequest, aState) {
      monkeysphere.log("++++ security change: " + aState + " ++++");
      monkeysphere.updateStatus(aWebProgress, aRequest, aState);
      return;
    },

    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {
      monkeysphere.log("++++ status change: " + aStatus + " ++++");
      return;
    },

    onProgressChange: function() {
      monkeysphere.log("++++ progress change ++++");
      return;
    },

    onLinkIconAvailable: function() {}
  },

////////////////////////////////////////////////////////////
// STATUS FUNCTION
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // Updates the status of the current page
  updateStatus: function(aWebProgress, aRequest, aState) {

    monkeysphere.log("==== updating status ====");

    try {
      var uri = aWebProgress.currentURI;
    } catch(e) {
      monkeysphere.log("no uri data available.  ignoring.");
      monkeysphere.setStatus();
      return;
    }

    ////////////////////////////////////////
    // check host
    try {
      var host = uri.host;
    } catch(e) {
      monkeysphere.log("host empty.  ignoring.");
      monkeysphere.setStatus();
      return;
    }

    ////////////////////////////////////////
    // test for https
    if(uri.scheme != "https") {
      monkeysphere.log("uri scheme: " + uri.scheme + ".  ignoring.");
      monkeysphere.setStatus();
      return;
    }

    ////////////////////////////////////////
    // check browser state
    monkeysphere.log("checking security state: " + aState);
    // if site secure...
    if(aState & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
      monkeysphere.log("  site cert already trusted by browser.  done.");
      monkeysphere.setStatus();
      return;

    // if site insecure continue
    } else if(aState & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE) {
      monkeysphere.log("  site is INSECURE");

    // else if unknown state continue
    } else {
      monkeysphere.log("  site state is unknown");
    }

    ////////////////////////////////////////
    // check exception (override) status
    monkeysphere.log("checking override status:");
    // if override set...
    if(monkeysphere.checkOverrideStatus(uri)) {
      // there's an override;
      // this is probably a manual user override so just return
      monkeysphere.log("  override set.  done.");
      monkeysphere.setStatus();
      return;

    // if no override continue
    } else {
      monkeysphere.log("  no override");
    }

    ////////////////////////////////////////
    // get site certificate
    monkeysphere.log("retrieving site certificate:");
    var cert = monkeysphere.getCertificate();
    if(!cert) {
      monkeysphere.setStatus(monkeysphere.states.ERROR,
			     monkeysphere.messages.getFormattedString("statusNoCert", [host]));
      return;
    }

    ////////////////////////////////////////
    // finally go ahead and query the agent
    monkeysphere.log("query agent");
    monkeysphere.queryAgent(aWebProgress, cert);
  },

  ////////////////////////////////////////////////////////////
  // set the status
  setStatus: function(state, message) {
    var panel = document.getElementById("monkeysphere-status");
    var icon = document.getElementById("monkeysphere-status-image");

    // the following happens when called from a dialog
    if(!panel || !icon) {
      panel = window.opener.document.getElementById("monkeysphere-status");
      icon = window.opener.document.getElementById("monkeysphere-status-image");
    }

    if(!state) {
      state = monkeysphere.states.NEUTRAL;
    }

    switch(state){
      case monkeysphere.states.PROGRESS:
	monkeysphere.log("set status: PROGRESS");
	icon.setAttribute("src", "chrome://monkeysphere/content/progress.gif");
        panel.hidden = false;
	break;
      case monkeysphere.states.VALID:
	monkeysphere.log("set status: VALID");
	icon.setAttribute("src", "chrome://monkeysphere/content/good.png");
        panel.hidden = false;
	break;
      case monkeysphere.states.INVALID:
	monkeysphere.log("set status: INVALID");
	icon.setAttribute("src", "chrome://monkeysphere/content/bad.png");
        panel.hidden = false;
	break;
      case monkeysphere.states.NEUTRAL:
        monkeysphere.log("clearing status (NEUTRAL).");
        icon.setAttribute("src", "");
        panel.hidden = true;
        break;
      case monkeysphere.states.ERROR:
        monkeysphere.log("set status: ERROR.");
        icon.setAttribute("src", "chrome://monkeysphere/content/error.png");
        monkeysphere.log("set message: '" + message + "'");
        panel.setAttribute("tooltiptext", message);
        panel.hidden = false;
        break;
    }
    if(message) {
      monkeysphere.log("set message: '" + message + "'");
      panel.setAttribute("tooltiptext", message);
    }
  },

////////////////////////////////////////////////////////////
// AGENT QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // query the validation agent
  queryAgent: function(aWebProgress, cert) {
    monkeysphere.log("#### querying validation agent ####");

    var agent_url = "http://localhost:8901/reviewcert";
    monkeysphere.log("agent_url: " + agent_url);

    var host = aWebProgress.currentURI.host;

    // set status that query in progress
    monkeysphere.setStatus(monkeysphere.states.PROGRESS,
			   monkeysphere.messages.getString("statusInProgress"));

    // get certificate info
    var cert_length = {};
    var dummy = {};
    var cert_data = cert.getRawDER(cert_length, dummy);

    // "agent post data"
    var apd = {
      context: "https",
      peer: host,
      pkc: {
	type: "x509der",
	data: cert_data
      }
    };

    monkeysphere.log("agent post data:");
    monkeysphere.log("  context: " + apd.context);
    monkeysphere.log("  peer: " + apd.peer);
    monkeysphere.log("  pkc.type: " + apd.pkc.type);
    //monkeysphere.log("  pkc.data: " + apd.pkc.data); // this can be big

    // make JSON query string
    var query = JSON.stringify(apd);

    monkeysphere.log("creating http request to " + agent_url);
    var client = new XMLHttpRequest();
    client.open("POST", agent_url, true);

    // set headers
    client.setRequestHeader("Content-Type", "application/json");
    client.setRequestHeader("Content-Length", query.length);
    client.setRequestHeader("Connection", "close");
    client.setRequestHeader("Accept", "application/json");

    // setup the state change function
    client.onreadystatechange = function() {
      monkeysphere.onAgentStateChange(client, aWebProgress, cert);
    };

    monkeysphere.log("sending query:");
    client.send(query);
    monkeysphere.log("query sent");
  },

  ////////////////////////////////////////////////////////////
  // when the XMLHttpRequest to the agent state changes
  onAgentStateChange: function(client, aWebProgress, cert) {
    var uri = aWebProgress.currentURI;

    monkeysphere.log("agent query state change: " + client.readyState);
    monkeysphere.log("  status: " + client.status);
    monkeysphere.log("  response: " + client.responseText);

    if (client.readyState == 4) {
      if (client.status == 200) {
	var response = JSON.parse(client.responseText);
	monkeysphere.log("validation agent response:");
	monkeysphere.log("  message: " + response.message);
        if (response.valid) {

	  // VALID!
          monkeysphere.log("SITE VERIFIED!");

	  // set security override
	  monkeysphere.securityOverride(uri, cert);

	  // set state valid
	  monkeysphere.setStatus(monkeysphere.states.VALID,
				 "Monkeysphere: " + response.message);

	  // reload
	  monkeysphere.log("reloading browser...");
	  try {
	    //var wn = DOM.getDocShellForWindow(aWebProgress.DOMWindow).QueryInterface(CI.nsIWebNavigation);
	    // var CI = Components.interfaces;
	    // var wn = window.QueryInterface(CI.nsIInterfaceRequestor)
            //   .getInterface(CI.nsIWebNavigation)
            //   .QueryInterface(CI.nsIDocShell);

            // wn.loadURI(aWebProgress.currentURI.spec,
            //   wn.LOAD_FLAGS_BYPASS_CACHE |
            //   wn.LOAD_FLAGS_IS_REFRESH,
            //   null, null, null);

	    // BAD
            //gBrowser.loadURI(uri.spec, null, null, null, null, null);
          } catch(ex) {
            dump(ex);
          }

        } else {
          monkeysphere.log("site not verified.");
	  monkeysphere.setStatus(monkeysphere.states.INVALID,
				 "Monkeysphere: " + response.message);
        }
      } else {
	monkeysphere.log("validation agent did not respond");
	monkeysphere.setStatus(monkeysphere.states.ERROR,
			       monkeysphere.messages.getString("agentError"));
	alert(monkeysphere.messages.getString("agentError"));
      }
    }
  },

////////////////////////////////////////////////////////////
// OVERRIDE FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
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

  ////////////////////////////////////////////////////////////
  // browser security override function
  securityOverride: function(uri, cert) {
    monkeysphere.log("**** CERT SECURITY OVERRIDE ****");

    var ssl_status = monkeysphere.getInvalidCertSSLStatus(uri);
    var overrideBits = 0;

    // set override bits
    if(ssl_status.isUntrusted) {
      monkeysphere.log("flag: ERROR_UNTRUSTED");
      overrideBits |= monkeysphere.override.ERROR_UNTRUSTED;
    }
    if(ssl_status.isDomainMismatch) {
      monkeysphere.log("flag: ERROR_MISMATCH");
      overrideBits |= monkeysphere.override.ERROR_MISMATCH;
    }
    if(ssl_status.isNotValidAtThisTime) {
      monkeysphere.log("flag: ERROR_TIME");
      overrideBits |= monkeysphere.override.ERROR_TIME;
    }

    monkeysphere.log("\thost: " + uri.asciiHost);
    monkeysphere.log("\tport: " + uri.port);
    monkeysphere.log("\tcert: " + cert);
    monkeysphere.log("\t md5: " + cert.md5Fingerprint);
    monkeysphere.log("\tsha1: " + cert.sha1Fingerprint);
    monkeysphere.log("\toverrideBits: " + overrideBits);

    monkeysphere.log("setting temporary override");
    monkeysphere.override.rememberValidityOverride(uri.asciiHost, uri.port,
						   cert,
						   overrideBits,
						   true);
  },

////////////////////////////////////////////////////////////
// CERT FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  getCertificate: function() {
    var cert = monkeysphere.getValidCert(gBrowser);
    if (cert) {
      monkeysphere.log("valid cert retrieved");
    } else {
      cert = monkeysphere.getInvalidCert(gBrowser);
      if (cert) {
	monkeysphere.log("invalid cert retrieved");
      } else {
	monkeysphere.log("could not retrieve cert");
	cert = null;
      }
    }
    monkeysphere.printCertInfo(cert);
    return cert;
  },

  ////////////////////////////////////////////////////////////
  // gets current certificate, if it PASSED the browser check
  getValidCert: function(browser) {
    try {
      var ui = browser.securityUI;
      var cert = ui.SSLStatus.serverCert;
    } catch (e) {
      //monkeysphere.log("error", e);
      return null;
    }
    return cert;
  },

  ////////////////////////////////////////////////////////////
  getInvalidCert: function(browser) {
    try {
      var uri = browser.currentURI;
      var ssl_status = monkeysphere.getInvalidCertSSLStatus(uri);
      var cert = ssl_status.QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
    } catch(e) {
      //monkeysphere.log("error", e);
      return null;
    }
    return cert;
  },

  ////////////////////////////////////////////////////////////
  // gets current certificat, if it FAILED the security check
  getInvalidCertSSLStatus: function(uri) {
    var recentCertsService =
      Components.classes["@mozilla.org/security/recentbadcerts;1"].getService(Components.interfaces.nsIRecentBadCertsService);
    if (!recentCertsService)
      return null;

    var port = uri.port;
    if(port == -1)
      port = 443;

    var hostWithPort = uri.host + ":" + port;
    var ssl_status = recentCertsService.getRecentBadCert(hostWithPort);
    if (!ssl_status)
      return null;

    return ssl_status;
  },

  // Print SSL certificate details
  // https://developer.mozilla.org/En/How_to_check_the_security_state_of_an_XMLHTTPRequest_over_SSL
  printCertInfo: function(cert) {
    const Ci = Components.interfaces;

    //if (secInfo instanceof Ci.nsISSLStatusProvider) {
    //var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;

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

  ////////////////////////////////////////////////////////////
  getFaviconText: function() {
    return document.getElementById("identity-box").tooltipText;
  },

  ////////////////////////////////////////////////////////////
  //Sets the tooltip and the text of the favicon popup on https sites
  setFaviconText: function(str) {
    document.getElementById("identity-box").tooltipText = str;
  },

  contextmenufunctions: {
    certs: function() {
      openDialog("chrome://pippki/content/certManager.xul", "Certificate Manager");
    },
    help: function() {
      gBrowser.loadOneTab("chrome://monkeysphere/locale/help.html",
      null, null, null, false);
    }
  }
};
