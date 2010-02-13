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
    ERR: -1, // there was a monkeysphere processing error
    NEU:  0, // neutral on this site (no icon)
    PRG:  1, // in progress (querying agent)
    VAL:  2, // processed and validated
    INV:  3  // processed and not validated
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
  log: function(flag, line) {
    var log_all = true;

    var log_flags = {
      "policy" : false,
      "query" : false,
      "main" : false,
      "error" :  false
    };

    var message = "monkeysphere: " + flag + ": " + line;
    // var consoleService = Components.classes["@mozilla.org/consoleservice;1"]
    //   .getService(Components.interfaces.nsIConsoleService);
    // consoleService.logStringMessage(msg);
    // return;

    try {
      if(!log_flags[flag] && !log_all)
	return;
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
      monkeysphere.log("debug: ", key + ":" + value);
    }
  },

////////////////////////////////////////////////////////////
// INITIALIZATION
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // initialization function
  init: function() {
    monkeysphere.log("main", "---- begin initialization ----");
    monkeysphere.clearStatus();
    monkeysphere.messages = document.getElementById("message_strings");
    monkeysphere.log("main", "creating listener.");
    getBrowser().addProgressListener(monkeysphere.listener,
				     Components.interfaces.nsIWebProgress.NOTIFY_STATE_DOCUMENT);
    // FIXME: do we need this?  what is it for?
    //setTimeout(function (){ monkeysphere.requeryAllTabs(gBrowser); }, 4000);
    monkeysphere.log("main", "---- initialization complete ----");
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
    onLocationChange: function(aWebProgress, aRequest, aURI) {
      monkeysphere.log("main", "++++ location change: " + aURI.spec + " ++++");
      try {
	monkeysphere.updateStatus(gBrowser);
      } catch(err) {
	monkeysphere.log("error", "listener: location change: " + err);
	monkeysphere.setStatus(monkeysphere.messages.getFormattedString("internalError", [err]));
      }
    },

    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
      return;
    },

    onSecurityChange: function(aWebProgress, aRequest, aState) {
      return;
    },

    onStatusChange: function() { },
    onProgressChange: function() { },
    onLinkIconAvailable: function() { }
  },

////////////////////////////////////////////////////////////
// STATUS FUNCTION
////////////////////////////////////////////////////////////

  clearStatus: function() {
    monkeysphere.setStatus(undefined, monkeysphere.states.NEU, undefined);
  },
  
  ////////////////////////////////////////////////////////////
  // set the status
  setStatus: function(uri, state, message) {
    var panel = document.getElementById("monkeysphere-status");
    var icon = document.getElementById("monkeysphere-status-image");

    // the following happens when called from a dialog
    if(!panel || !icon) {
      panel = window.opener.document.getElementById("monkeysphere-status");
      icon = window.opener.document.getElementById("monkeysphere-status-image");
    }

    switch(state){
      case monkeysphere.states.PRG:
	monkeysphere.log("main", "set status: PRG");
	icon.setAttribute("src", "chrome://monkeysphere/content/progress.gif");
        panel.hidden = false;
	break;
      case monkeysphere.states.VAL:
	monkeysphere.log("main", "set status: VAL");
	icon.setAttribute("src", "chrome://monkeysphere/content/good.png");
        panel.hidden = false;
	break;
      case monkeysphere.states.INV:
	monkeysphere.log("main", "set status: INV");
	icon.setAttribute("src", "chrome://monkeysphere/content/bad.png");
        panel.hidden = false;
	break;
      case monkeysphere.states.NEU:
        monkeysphere.log("main", "clearing status (NEU).");
        icon.setAttribute("src", "");
        panel.hidden = true;
        break;
      case monkeysphere.states.ERR:
        monkeysphere.log("main", "set status: ERR.");
        icon.setAttribute("src", "chrome://monkeysphere/content/error.png");
        monkeysphere.log("main", "set message: '" + message + "'");
        panel.setAttribute("tooltiptext", message);
        panel.hidden = false;
        break;
    }
    if (message) {
      monkeysphere.log("main", "set message: '" + message + "'");
      panel.setAttribute("tooltiptext", message);
    }
  },

  ////////////////////////////////////////////////////////////
  // Updates the status of the current page
  updateStatus: function(browser) {
    monkeysphere.log("main", "==== updating status ====");

    const Ci = Components.interfaces;

    if(!browser) {
      monkeysphere.log("error", "no browser!?!");
      return;
    }

    ////////////////////////////////////////
    // check uri
    var uri = browser.currentURI;
    monkeysphere.log("main", "checking uri:");
    if(uri) {
      monkeysphere.log("main", " uri spec: " + uri.spec);
    } else {
      monkeysphere.log("main", " no uri data available. ignoring.");
      monkeysphere.Status();
      return;
    }

    ////////////////////////////////////////
    // check host
    monkeysphere.log("main", "checking host:");
    try {
      monkeysphere.log("main", " host: " + uri.host);
    } catch(err) {
      monkeysphere.log("main", " missing host name. ignoring.");
      monkeysphere.clearStatus();
      return;
    }
    if(!uri.host) {
      monkeysphere.log("main", " host empty. ignoring.");
      return;
    }

    ////////////////////////////////////////
    // test for https
    monkeysphere.log("main", "checking uri scheme:");
    monkeysphere.log("main", " scheme: " + uri.scheme);
    if(uri.scheme != "https") {
      monkeysphere.log("main", " uri scheme not https. ignoring.");
      monkeysphere.clearStatus();
      return;
    } else {
      monkeysphere.log("main", " scheme https.");
    }

    ////////////////////////////////////////
    // check browser state
    monkeysphere.log("main", "checking security state:");
    var state = browser.securityUI.state;
    monkeysphere.log("main", " state: " + state);
    // if site secure...
    if(state & Ci.nsIWebProgressListener.STATE_IS_SECURE) {
      monkeysphere.log("main", " site cert already trusted by browser.");
      return;
    // if site insecure continue
    } else if(state & Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
      monkeysphere.log("main", " state INSECURE.");
    // else if unknown state continue
    } else {
      monkeysphere.log("main", " state UNKNOWN.");
    }

    ////////////////////////////////////////
    // check exception (override) status
    monkeysphere.log("main", "checking override status:");

    // if override set...
    if(monkeysphere.checkOverrideStatus(uri)) {
      monkeysphere.log("main", " override set.");

      // there's an override;
      // this is probably a manual user override so just return
      return;

    // if no override...
    } else {
      monkeysphere.log("main", " no override.");
      // overwise proceed
    }

    ////////////////////////////////////////
    // get site certificate
    monkeysphere.log("main", "retrieving site certificate:");
    var cert = monkeysphere.getCertificate(browser);
    if(!cert) {
      monkeysphere.setStatus(uri, monkeysphere.states.ERR, monkeysphere.messages.getFormattedString("statusNoCert", [uri.host]));
      return;
    }

    ////////////////////////////////////////
    // finally go ahead and query the agent
    monkeysphere.log("main", "#### querying validation agent ####");
    monkeysphere.queryAgent(browser, cert);
  },

////////////////////////////////////////////////////////////
// AGENT QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // query the validation agent
  queryAgent: function(browser, cert) {
    var uri = browser.currentURI;

    var agent_url = "http://localhost:8901/reviewcert";
    monkeysphere.log("query", "agent_url: " + agent_url);

    // set status that query in progress
    monkeysphere.setStatus(uri,
			   monkeysphere.states.PRG,
			   monkeysphere.messages.getString("statusInProgress"));

    // get certificate info
    var cert_length = {};
    var dummy = {};
    var cert_data = cert.getRawDER(cert_length, dummy);

    // "agent post data"
    var apd = {
      context: "https",
      peer: uri.host,
      pkc: {
	type: "x509der",
	data: cert_data
      }
    };
    monkeysphere.log("query", " context: " + apd.context);
    monkeysphere.log("query", " peer: " + apd.peer);
    monkeysphere.log("query", " pkc.type: " + apd.pkc.type);
    //monkeysphere.log("query", " pkc.data: " + apd.pkc.data); // this can be big

    // make JSON query string
    var query = JSON.stringify(apd);

    monkeysphere.log("query", "creating http request to " + agent_url);
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

    monkeysphere.log("query", "sending query:");
    client.send(query);
    monkeysphere.log("query", "query sent");
  },

  ////////////////////////////////////////////////////////////
  // when the XMLHttpRequest to the agent state changes
  onAgentStateChange: function(client, browser, cert) {
    var uri = browser.currentURI;

    monkeysphere.log("query", "state change: " + client.readyState);
    monkeysphere.log("query", " status: " + client.status);
    monkeysphere.log("query", " response: " + client.responseText);

    if (client.readyState == 4) {
      if (client.status == 200) {
	var response = JSON.parse(client.responseText);
	monkeysphere.log("query", "validation agent response:");
	monkeysphere.log("query", "  message: " + response.message);
        if (response.valid) {
          monkeysphere.log("query", "  site verified!");
	  monkeysphere.securityOverride(browser, cert, response);
        } else {
          monkeysphere.log("query", "  site not verified.");
	  monkeysphere.setStatus(uri,
				 monkeysphere.states.INV,
				 "Monkeysphere: " + response.message);
        }
      } else {
	monkeysphere.log("error", "validation agent did not respond");
	monkeysphere.setStatus(undefined, monkeysphere.states.ERR, monkeysphere.messages.getString("agentError"));
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
    monkeysphere.log("debug", "current override status:");
    status = monkeysphere.override.getValidityOverride(uri.asciiHost, uri.port,
						       aHashAlg,
						       aFingerprint,
						       aOverrideBits,
						       aIsTemporary);
    monkeysphere.log("debug", "\tstatus: " + status);
    monkeysphere.log("debug", "\tfingerprint: " + aFingerprint);
    monkeysphere.log("debug", "\toverride bit: " + aOverrideBits);
    monkeysphere.log("debug", "\ttemporary: " + aIsTemporary);
    return status;
  },

  ////////////////////////////////////////////////////////////
  // browser security override function
  securityOverride: function(browser, cert, agent_response) {
    monkeysphere.log("policy", "**** CERT SECURITY OVERRIDE REQUESTED ****");

    var uri = browser.currentURI;
    var ssl_status = monkeysphere.getInvalidCertSSLStatus(uri);
    var overrideBits = 0;

    // set override bits
    if(ssl_status.isUntrusted) {
      monkeysphere.log("policy", "flag: ERROR_UNTRUSTED");
      overrideBits |= monkeysphere.override.ERROR_UNTRUSTED;
    }
    if(ssl_status.isDomainMismatch) {
      monkeysphere.log("policy", "flag: ERROR_MISMATCH");
      overrideBits |= monkeysphere.override.ERROR_MISMATCH;
    }
    if(ssl_status.isNotValidAtThisTime) {
      monkeysphere.log("policy", "flag: ERROR_TIME");
      overrideBits |= monkeysphere.override.ERROR_TIME;
    }

    monkeysphere.log("policy", "  host:port: " + uri.asciiHost + ":" + uri.port);
    monkeysphere.log("policy", "  cert: " + cert);
    monkeysphere.log("policy", "  cert md5: " + cert.md5Fingerprint);
    monkeysphere.log("policy", "  cert sha1: " + cert.sha1Fingerprint);
    monkeysphere.log("policy", "  overrideBits: " + overrideBits);

    // check override status
    monkeysphere.checkOverrideStatus(uri);

    monkeysphere.log("policy", "setting temporary override");
    monkeysphere.override.rememberValidityOverride(uri.asciiHost, uri.port,
						   cert,
						   overrideBits,
						   true);

    // check override status
    monkeysphere.checkOverrideStatus(uri);

    // set status valid!
    monkeysphere.setStatus(uri,
			   monkeysphere.states.VAL,
			   "Monkeysphere: " + agent_response.message);

    monkeysphere.log("policy", "browser reload");
    // FIXME: why the "timeout"?  what's it for?
    setTimeout(
      function() {
	browser.loadURI(uri.spec);
      },
      25);
  },

////////////////////////////////////////////////////////////
// CERT FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  getCertificate: function(browser) {
    var cert = monkeysphere.getValidCert(browser);
    if (cert) {
      monkeysphere.log("main", "valid cert retrieved");
    } else {
      cert = monkeysphere.getInvalidCert(browser);
      if (cert) {
	monkeysphere.log("main", "invalid cert retrieved");
      } else {
	monkeysphere.log("error", "could not retrieve cert");
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

    monkeysphere.log("debug", "certificate status:");
    switch (cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer)) {
    case Ci.nsIX509Cert.VERIFIED_OK:
      monkeysphere.log("debug", "\tSSL status: OK");
      break;
    case Ci.nsIX509Cert.NOT_VERIFIED_UNKNOWN:
      monkeysphere.log("debug", "\tSSL status: not verfied/unknown");
      break;
    case Ci.nsIX509Cert.CERT_REVOKED:
      monkeysphere.log("debug", "\tSSL status: revoked");
      break;
    case Ci.nsIX509Cert.CERT_EXPIRED:
      monkeysphere.log("debug", "\tSSL status: expired");
      break;
    case Ci.nsIX509Cert.CERT_NOT_TRUSTED:
      monkeysphere.log("debug", "\tSSL status: not trusted");
      break;
    case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED:
      monkeysphere.log("debug", "\tSSL status: issuer not trusted");
      break;
    case Ci.nsIX509Cert.ISSUER_UNKNOWN:
      monkeysphere.log("debug", "\tSSL status: issuer unknown");
      break;
    case Ci.nsIX509Cert.INVALID_CA:
      monkeysphere.log("debug", "\tSSL status: invalid CA");
      break;
    default:
      monkeysphere.log("debug", "\tSSL status: unexpected failure");
      break;
    }
    monkeysphere.log("debug", "\tCommon Name: " + cert.commonName);
    monkeysphere.log("debug", "\tOrganisation: " + cert.organization);
    monkeysphere.log("debug", "\tIssuer: " + cert.issuerOrganization);
    monkeysphere.log("debug", "\tSHA1 fingerprint: " + cert.sha1Fingerprint);

    var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
    monkeysphere.log("debug", "\tValid from: " + validity.notBeforeGMT);
    monkeysphere.log("debug", "\tValid until: " + validity.notAfterGMT);
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
