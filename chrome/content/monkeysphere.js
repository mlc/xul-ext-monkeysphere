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
    ERROR:     -1, // there was a monkeysphere processing error
    NEUTRAL:    0, // neutral on this site (no icon)
    INPROGRESS: 1, // in progress (querying agent)
    VALID:      2, // processed and validated
    NOTVALID:   3  // processed and not validated
  },

  // agent URL from environment variable
  // "http://localhost:8901" <-- NO TRAILING SLASH
  agent_url: [],

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

    // clear status
    monkeysphere.setStatus();

    // get localization messages
    monkeysphere.messages = document.getElementById("message_strings");

    // get the agent URL from the environment
    // https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsIEnvironment
    monkeysphere.agent_url = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("MONKEYSPHERE_VALIDATION_AGENT_URL");
    // return error if agent URL not set
    if(!monkeysphere.agent_url) {
      var message = "MONKEYSPHERE_VALIDATION_AGENT_URL environment variable not set.";
      alert(message);
      monkeysphere.setStatus(monkeysphere.states.ERROR, message);
      return;
    } else {
      monkeysphere.log("agent url: " + monkeysphere.agent_url);
    }

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
      monkeysphere.log("++++ location change: ");
      monkeysphere.updateStatus(aLocation);
    },

    onProgressChange: function() {},
    onSecurityChange: function() {},
    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {},
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {}
  },

  // https://developer.mozilla.org/en/Listening_to_events_on_all_tabs
  tabProgressListener: {
    onSecurityChange: function(aBrowser, aWebProgress, aRequest, aState) {
      monkeysphere.log("++++ security change: ");
      monkeysphere.checkSite(aBrowser, aState);
    },

    onLocationChange: function() {},
    onProgressChange: function() {},
    onStateChange: function() {},
    onStatusChange: function() {}
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
    var uri = browser.currentURI;

    // if uri not relevant, return
    if(!monkeysphere.isRelevantURI(uri)) {
      monkeysphere.log("done.");
      return;
    }

    ////////////////////////////////////////
    // check browser state
    monkeysphere.log("checking security state: " + state);
    // if site secure...
    if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
      monkeysphere.log("  site state SECURE.");
      monkeysphere.log("done.");
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
    // check site cert
    // FIXME: what's the right checks to do here?
    // FIXME: how do we make it so that a reload can recheck?
    if(monkeysphere.cache.isSet(uri)) {
      if(monkeysphere.cache.cert(uri) == cert.sha1Fingerprint) {
	monkeysphere.log("site cached.");
	return;
      }
    }

    ////////////////////////////////////////
    // finally go ahead and query the agent
    monkeysphere.log("querying agent...");
    monkeysphere.queryAgent(browser, cert);
  },

////////////////////////////////////////////////////////////
// STATUS FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // update status
  updateStatus: function(uri) {
    // return if uri not relevant
    if(!monkeysphere.isRelevantURI(uri)) {
      monkeysphere.setStatus();
      return;
    }

    // clear status and return if no cache for this site
    if(!monkeysphere.cache.isSet(uri)) {
      monkeysphere.setStatus();
      return;
    }

    // otherwise, set the status from the cache
    monkeysphere.log("setting status from cache");
    monkeysphere.setStatus(monkeysphere.cache.state(uri),
			   monkeysphere.cache.message(uri));
  },

  //////////////////////////////////////////////////////////
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
      case monkeysphere.states.INPROGRESS:
	monkeysphere.log("set status: INPROGRESS");
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
        monkeysphere.log("set status: NEUTRAL");
        icon.setAttribute("src", "");
        panel.hidden = true;
        break;
      case monkeysphere.states.ERROR:
        monkeysphere.log("set status: ERROR");
        icon.setAttribute("src", "chrome://monkeysphere/content/error.png");
        panel.hidden = false;
        break;
    }

    if(message) {
      monkeysphere.log("set message: " + message);
      panel.setAttribute("tooltiptext", message);
    }
  },

////////////////////////////////////////////////////////////
// CACHE
////////////////////////////////////////////////////////////

  // return full uid: scheme://host[:port]
  uid: function(uri) {
    var host = uri.host;
    var port = uri.port;
    if(port == -1)
      port = 443;
    if(port != 443)
      host = host + ":" + port;
    return uri.scheme + '://' + host;
  },

  // cache
  cache: {
    array: {},

    set: function(uri, state, cert, message) {
      var uid = monkeysphere.uid(uri);
      monkeysphere.log("set cache: " + uid);
      monkeysphere.log("\tstate: " + state);
      monkeysphere.log("\tcert: " + cert.sha1Fingerprint);
      monkeysphere.log("\tmessage: " + message);
      if(!monkeysphere.cache.array[uid])
	monkeysphere.cache.array[uid] = {};
      monkeysphere.cache.array[uid].state = state;
      monkeysphere.cache.array[uid].cert = cert.sha1Fingerprint;
      monkeysphere.cache.array[uid].message = message;
      return;
    },

    isSet: function(uri, state, cert, message) {
      var uid = monkeysphere.uid(uri);
      if(monkeysphere.cache.array[uid])
	return true;
      else
	return false;
    },

    state: function(uri) {
      var uid = monkeysphere.uid(uri);
      if(monkeysphere.cache.array[uid])
	return monkeysphere.cache.array[uid].state;
      else
	return null;
    },

    cert: function(uri) {
      var uid = monkeysphere.uid(uri);
      if(monkeysphere.cache.array[uid])
	return monkeysphere.cache.array[uid].cert;
      else
	return null;
    },

    message: function(uri) {
      var uid = monkeysphere.uid(uri);
      if(monkeysphere.cache.array[uid])
	return monkeysphere.cache.array[uid].message;
      else
	return null;
    },

    clear: function(uri) {
      var uid = monkeysphere.uid(uri);
      monkeysphere.log("clear cache: " + uid);
      if(monkeysphere.cache.array[uid])
	monkeysphere.cache.array[uid] = {};
      return;
    }
  },

////////////////////////////////////////////////////////////
// AGENT QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // query the validation agent
  queryAgent: function(browser, cert) {
    monkeysphere.log("#### querying validation agent ####");

    monkeysphere.log("agent_url: " + monkeysphere.agent_url);

    var uri = browser.currentURI;
    var host = uri.host;

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

    var request_url = monkeysphere.agent_url + "/reviewcert";
    monkeysphere.log("creating http request to " + request_url);
    var client = new XMLHttpRequest();
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
    monkeysphere.cache.set(uri, monkeysphere.states.INPROGRESS, cert, "Querying Monkeysphere validation agent...");
    browser.webNavigation.reload(nsIWebNavigation.LOAD_FLAGS_NONE);
  },

  //////////////////////////////////////////////////////////
  // when the XMLHttpRequest to the agent state changes
  onAgentStateChange: function(client, browser, cert) {
    var uri = browser.currentURI;

    monkeysphere.log("agent query state change: " + client.readyState);
    monkeysphere.log("  status: " + client.status);
    monkeysphere.log("  response: " + client.responseText);

    if (client.readyState == 4) {
      if (client.status == 200) {

	var response = JSON.parse(client.responseText);

        if (response.valid) {

	  // VALID!
	  monkeysphere.log("SITE VERIFIED!");
	  monkeysphere.cache.set(uri, monkeysphere.states.VALID, cert, response.message);
	  monkeysphere.securityOverride(uri, cert);

        } else {

	  // NOT VALID
	  monkeysphere.log("site not verified.");
	  monkeysphere.cache.set(uri, monkeysphere.states.NOTVALID, cert, response.message);
        }

      } else {
	monkeysphere.log("validation agent did not respond.");
	//alert(monkeysphere.messages.getString("agentError"));
	monkeysphere.cache.set(uri, monkeysphere.states.ERROR, cert, monkeysphere.messages.getString("agentError"));
      }

      // reload page
      monkeysphere.log("reloading browser...");
      browser.webNavigation.reload(nsIWebNavigation.LOAD_FLAGS_NONE);
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
// CERT FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
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
      var uri = gBrowser.currentURI;
      monkeysphere.clearOverride(uri);
      monkeysphere.cache.clear(uri);
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
