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
    NOTVALID: 3  // processed and not validated
  },

  // override service class
  // http://www.oxymoronical.com/experiments/xpcomref/applications/Firefox/3.5/interfaces/nsICertOverrideService
  override: Components.classes["@mozilla.org/security/certoverride;1"].getService(Components.interfaces.nsICertOverrideService),

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
      monkeysphere.log("dump: " + key + " = " + obj[key]);
    }
  },

////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
////////////////////////////////////////////////////////////

  // return full uid: scheme://host[:port]
  uid: function(uri) {
    var port = uri.port;
    if(port == -1)
      port = 443;

    var host = uri.host;
    if(port != 443)
      host = host + ":" + port;

    return uri.scheme + '://' + host;
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
    monkeysphere.log("creating listener");
    gBrowser.addProgressListener(monkeysphere.progressListener);
    gBrowser.addTabsProgressListener(monkeysphere.tabProgressListener);
    monkeysphere.log("---- initialization complete ----");
  },

////////////////////////////////////////////////////////////
// LISTENERS
////////////////////////////////////////////////////////////

  // https://developer.mozilla.org/en/nsIWebProgressListener

  // https://developer.mozilla.org/en/Listening_to_events_on_all_tabs
  tabProgressListener: {
    onSecurityChange: function(aBrowser, aWebProgress, aRequest, aState) {
      monkeysphere.log("++++ security change: " + aBrowser.currentURI.host + " : " + aState);

      ////////////////////////////////////////
      // check uri
      try {
	var uri = aBrowser.currentURI;
      } catch(e) {
	monkeysphere.log("no uri data available.");
	return;
      }

      ////////////////////////////////////////
      // check host
      if(!uri.host) {
	monkeysphere.log("host empty.");
	return;
      }

      ////////////////////////////////////////
      // test for https
      if(uri.scheme != "https") {
	monkeysphere.log("scheme not https.");
	return;
      }

      ////////////////////////////////////////
      // check browser state
      monkeysphere.log("checking security state: " + aState);
      // if site secure...
      if(aState & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
	monkeysphere.log("  site cert already trusted by browser.");
	return;

      // if site insecure continue
      } else if(aState & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE) {
	monkeysphere.log("  site is INSECURE");

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
      monkeysphere.log("query agent");
      monkeysphere.queryAgent(aBrowser, cert);
      return;
    }
  },

  progressListener: {
    onLocationChange: function(aWebProgress, aRequest, aLocation) {
      monkeysphere.log("++++ location change: " + aLocation.host);

      // set status
      // FIXME: based on what?  how to cache monkeysphere status?
      // var message = SOMETHING FROM CACHE?
      // monkeysphere.setStatus();
      // monkeysphere.setStatus(monkeysphere.states.PROGRESS,
      // 			     monkeysphere.messages.getString("statusInProgress"));
      // monkeysphere.setStatus(monkeysphere.states.VALID,
      // 			     "Monkeysphere: " + message);
      // monkeysphere.setStatus(monkeysphere.states.NOTVALID,
      // 			     "Monkeysphere: " + message);
      // monkeysphere.setStatus(monkeysphere.states.ERROR,
      // 			     monkeysphere.messages.getString("agentError"));
    }
  },

////////////////////////////////////////////////////////////
// STATUS FUNCTION
////////////////////////////////////////////////////////////

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
      case monkeysphere.states.NOTVALID:
	monkeysphere.log("set status: NOTVALID");
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
      monkeysphere.log("set message: " + message);
      panel.setAttribute("tooltiptext", message);
    }
  },

////////////////////////////////////////////////////////////
// AGENT QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // query the validation agent
  queryAgent: function(browser, cert) {
    monkeysphere.log("#### querying validation agent ####");

    var agent_url = "http://localhost:8901/reviewcert";
    monkeysphere.log("agent_url: " + agent_url);

    var host = browser.currentURI.host;

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
      monkeysphere.onAgentStateChange(client, browser, cert);
    };

    monkeysphere.log("sending query:");
    client.send(query);
    monkeysphere.log("query sent");
  },

  ////////////////////////////////////////////////////////////
  // when the XMLHttpRequest to the agent state changes
  onAgentStateChange: function(client, browser, cert) {
    var uri = browser.currentURI;

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

	  // reload
	  monkeysphere.log("reloading browser...");
	  browser.webNavigation.reload(nsIWebNavigation.LOAD_FLAGS_NONE);

        } else {
          monkeysphere.log("site not verified.");
        }
      } else {
	monkeysphere.log("validation agent did not respond");
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

    monkeysphere.log("setting temporary override:");
    monkeysphere.log("\thost: " + uri.asciiHost);
    monkeysphere.log("\tport: " + uri.port);
    monkeysphere.log("\tcert: " + cert);
    monkeysphere.log("\t md5: " + cert.md5Fingerprint);
    monkeysphere.log("\tsha1: " + cert.sha1Fingerprint);
    monkeysphere.log("\toverrideBits: " + overrideBits);

    monkeysphere.override.rememberValidityOverride(uri.asciiHost, uri.port,
						   cert,
						   overrideBits,
						   true);
  },

  ////////////////////////////////////////////////////////////
  // clear an override
  clearOverride: function(uri) {
    monkeysphere.log("clearly temporary override");
    monkeysphere.override.clearValidityOverride(uri.asciiHost, uri.port);
  },

////////////////////////////////////////////////////////////
// CERT FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // FWIW, aWebProgress listener has:
  // securityUI = [xpconnect wrapped (nsISupports, nsISecureBrowserUI, nsISSLStatusProvider)]
  // but i don't think it can be used because it doesn't hold invalid cert info
  getCertificate: function(uri) {
    try {
      var cert = monkeysphere.getInvalidCertSSLStatus(uri).QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
      monkeysphere.printCertInfo(cert);
      return cert;
    } catch(e) {
      return null;
    }
  },

  ////////////////////////////////////////////////////////////
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
