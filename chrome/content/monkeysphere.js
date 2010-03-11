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

  // select agent URL from environment variable or explicitly-set preference.
  // "http://localhost:8901" <-- NO TRAILING SLASH
  var agent_socket = function() {
    var envvar = "MONKEYSPHERE_VALIDATION_AGENT_SOCKET";;
    try {
      envvar = monkeysphere.prefs.getCharPref("validation_agent_socket_environment_variable");
    } catch (e) {
      log("falling back to built-in environment variable: " + envvar);
    }
    log("using environment variable " + envvar);
    // get the agent URL from the environment
    // https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsIEnvironment
    var ret = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get(envvar);
    // return error if agent URL not set
    if(!ret) {
      ret = "http://localhost:8901";;
      try {
        ret = monkeysphere.prefs.getCharPref("default_socket");
      } catch (e) {
        log("falling back to built-in default socket location: " + ret);
      }

      log(envvar + " environment variable not set.  Using default of " + ret);
    }
    // replace trailing slashes
    ret = ret.replace(/\/*$/, '');
    log("agent socket: " + ret);
      
    return ret;
  };
  
  // certificate override service class
  // http://www.oxymoronical.com/experiments/xpcomref/applications/Firefox/3.5/interfaces/nsICertOverrideService
  var certOverrideService = Components.classes["@mozilla.org/security/certoverride;1"].getService(Components.interfaces.nsICertOverrideService);
                      
  // preferences in about:config
  var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.monkeysphere.");

////////////////////////////////////////////////////////////
// LOG FUNCTIONS
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  var log = function(line) {
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
  };

  var objdump = function(obj) {
    for (var key in obj) {
      log("dump: " + key + " = " + obj[key]);
    }
  };

  return {

////////////////////////////////////////////////////////////
// INITIALIZATION
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // initialization function
  init: function() {
    log("---- begin initialization ----");

    // get localization messages
    monkeysphere.messages = document.getElementById("message_strings");

    // create event listeners
    log("creating listeners...");
    gBrowser.addProgressListener(monkeysphere.progressListener);
    gBrowser.addTabsProgressListener(monkeysphere.tabProgressListener);

    log("---- initialization complete ----");
  },

////////////////////////////////////////////////////////////
// LISTENERS
////////////////////////////////////////////////////////////

  // https://developer.mozilla.org/en/nsIWebProgressListener
  progressListener: {
    onLocationChange: function(aWebProgress, aRequest, aLocation) {
      log("++++ PL location change: " + aLocation.prePath);
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
      log("++++ tabPL security change: ");
      monkeysphere.checkSite(aBrowser, aState);
    },

    onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation) {
      //log("++++ tabPL location change: " + aLocation.prePath);
    },
    onProgressChange: function(aBrowser, awebProgress, aRequest, curSelfProgress, maxSelfProgress, curTotalProgress, maxTotalProgress) {
      //log("++++ tabPL progress change: " + curSelfProgress);
    },
    onStateChange: function(aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
      log("++++ tabPL state change: " + aRequest);
      monkeysphere.updateDisplay();
    },
    onStatusChange: function(aBrowser, aWebProgress, aRequest, aStatus, aMessage) {
      //log("++++ tabPL status change: " + aRequest);
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
      log("host data empty.");
      return null;
    }

    ////////////////////////////////////////
    // check scheme
    try {
      var scheme = uri.scheme;
    } catch(e) {
      log("scheme data empty.");
      return null;
    }

    log("url: " + uri.asciiSpec);

    ////////////////////////////////////////
    // check if scheme is https
    if(scheme != "https") {
      log("scheme not https.");
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
    log("check site:");

    var uri = browser.currentURI;

    // if uri not relevant, return
    if(!monkeysphere.isRelevantURI(uri)) {
      monkeysphere.setStatus(browser, 'NEUTRAL');
      return;
    }

    ////////////////////////////////////////
    // check browser state
    log("checking security state: " + state);
    // if site secure...
    if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
      log("  site state SECURE.");

      // if a monkeysphere-generated cert override is being used by this connection, then we should be setting the status from the override
      var cert = browser.securityUI.SSLStatus.serverCert;
      var apd = monkeysphere.createAgentPostData(uri, cert);
      var response = monkeysphere.overrides.response(apd);
      if ( typeof response === 'undefined' ) {
        monkeysphere.setStatus(browser, 'NEUTRAL');
      } else {
        monkeysphere.setStatus(browser, 'VALID', response.message);
      }
      return;

    // if site insecure continue
    } else if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE) {
      log("  site state INSECURE");

    // else if unknown state continue
    } else {
      log("  site state is unknown");
    }

    ////////////////////////////////////////
    // get site certificate
    log("retrieving site certificate:");
    var cert = monkeysphere.getInvalidCert(uri);

    ////////////////////////////////////////
    // finally go ahead and query the agent
    log("querying agent...");
    monkeysphere.queryAgent(browser, cert);
  },

  //////////////////////////////////////////////////////////
  // set site monkeysphere status
  setStatus: function(browser, state, message) {
    if ( typeof message === 'undefined' ) {
      var key = "status" + state;
      message = monkeysphere.messages.getString(key);
    }
    log("set browser status: " + state + ', ' + message);
    browser.monkeysphere = { state: state, message: message };
  },

  //////////////////////////////////////////////////////////
  // clear site monkeysphere status for browser
  clearStatus: function(browser) {
    log("clear browser status");
    delete browser.monkeysphere;
  },

////////////////////////////////////////////////////////////
// UPDATE DISPLAY
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // update the display for the currently visible browser
  updateDisplay: function() {
    log("update display:");

    var browser = gBrowser.selectedBrowser;
    var panel = document.getElementById("monkeysphere-status");
    var icon = document.getElementById("monkeysphere-status-image");

    // the following happens when called from a dialog
    if(!panel || !icon) {
      log("  panel/icon not available; falling back to window.opener");
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

    log("  state: " + state);
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

    log("  message: " + message);
    panel.setAttribute("tooltiptext", message);
  },

////////////////////////////////////////////////////////////
// AGENT QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  createAgentPostData: function(uri, cert) {
    // get certificate info
    var cert_length = {};
    var dummy = {};
    var cert_data = cert.getRawDER(cert_length, dummy);

    // "agent post data"
    var apd = {
      uri: uri,
      cert: cert,
      data: {
        context: uri.scheme,
        peer: uri.hostPort,
        pkc: {
          type: "x509der",
          data: cert_data
        }
      },
      toJSON: function() {
        return JSON.stringify(this.data);
      },
      toOverrideLabel: function() {
        return this.data.context + '|' + this.data.peer + '|' + this.data.pkc.type + '|' + this.data.pkc.data;
      },
      log: function() {
        log("agent post data:");
        log("  context: " + this.data.context);
        log("  peer: " + this.data.peer);
        log("  pkc.type: " + this.data.pkc.type);
        //log("  pkc.data: " + this.data.pkc.data); // this can be big
        //log("  JSON: " + this.toJSON());
      }
    };

    return apd;
  },

  //////////////////////////////////////////////////////////
  // query the validation agent
  queryAgent: function(browser, cert) {
    log("#### querying validation agent ####");
    var socket = agent_socket();

    var uri = browser.currentURI;

    // make the client request object
    var client = new XMLHttpRequest();

    // make JSON query string
    client.apd = monkeysphere.createAgentPostData(uri, cert);
    client.apd.log();
    var query = client.apd.toJSON();

    var request_url = socket + "/reviewcert";
    log("creating http request to " + request_url);
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

    log("sending query...");
    client.send(query);
    log("query sent");
    monkeysphere.setStatus(browser, 'INPROGRESS');
  },

  //////////////////////////////////////////////////////////
  // when the XMLHttpRequest to the agent state changes
  onAgentStateChange: function(client, browser, cert) {
    log("agent query state change: " + client.readyState);
    log("  status: " + client.status);
    log("  response: " + client.responseText);

    if (client.readyState == 4) {
      if (client.status == 200) {

        var response = JSON.parse(client.responseText);

        if (response.valid) {

          // VALID!
          log("SITE VERIFIED!");
          monkeysphere.overrides.set(client.apd, response);
          monkeysphere.setStatus(browser, 'VALID', response.message);

          // reload page
          log("reloading browser...");
          browser.webNavigation.reload(nsIWebNavigation.LOAD_FLAGS_NONE);

        } else {

          // NOT VALID
          log("site not verified.");
          monkeysphere.setStatus(browser, 'NOTVALID', response.message);

        }
      } else {
        log("validation agent did not respond.");
        //alert(monkeysphere.messages.getString("agentError"));
        monkeysphere.setStatus(browser, 'ERROR', monkeysphere.messages.getString('noResponseFromAgent'));
      }

      // update the current display, so that if we're looking at the
      // browser being processed, the result will be immediately displayed
      monkeysphere.updateDisplay();
    }
  },

////////////////////////////////////////////////////////////
// OVERRIDE CACHE OBJECT
////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // object to store and retrieve data about monkeysphere status for sites
  // uses string of apd as key, and agent response as data
  overrides: (function() {

    // response cache object
    var responses = {};

    return {

      // set override
      set: function(apd, agentResponse) {
        log("**** SET OVERRIDE ****");

        var uri = apd.uri;
        var cert = apd.cert;

        var SSLStatus = monkeysphere.getInvalidCertSSLStatus(uri);
        var overrideBits = 0;

        // set override bits
        // FIXME: should this just be for all flags by default?
        if(SSLStatus.isUntrusted) {
          log("flag: ERROR_UNTRUSTED");
          overrideBits |= certOverrideService.ERROR_UNTRUSTED;
        }
        if(SSLStatus.isDomainMismatch) {
          log("flag: ERROR_MISMATCH");
          overrideBits |= certOverrideService.ERROR_MISMATCH;
        }
        if(SSLStatus.isNotValidAtThisTime) {
          log("flag: ERROR_TIME");
          overrideBits |= certOverrideService.ERROR_TIME;
        }

        log("overrideBits: " + overrideBits);

        log("set cert override: " + uri.asciiHost + ":" + uri.port);
        certOverrideService.rememberValidityOverride(uri.asciiHost, uri.port,
                                                                  cert,
                                                                  overrideBits,
                                                                  true);

        log("setting cache");
        apd.log();
        responses[apd.toOverrideLabel()] = agentResponse;
      },

      // return response object
      response: function(apd) {
        return responses[apd.toOverrideLabel()];
      },

      // return override status as bool, true for override set
      certStatus: function(apd) {
        var uri = apd.uri;
        var aHashAlg = {};
        var aFingerprint = {};
        var aOverrideBits = {};
        var aIsTemporary = {};
        return certOverrideService.getValidityOverride(uri.asciiHost, uri.port,
                                                                    aHashAlg,
                                                                    aFingerprint,
                                                                    aOverrideBits,
                                                                    aIsTemporary);
      },

      // clear override
      clear: function(apd) {
        log("**** CLEAR OVERRIDE ****");
        var uri = apd.uri;
        log("clearing cert override");
        certOverrideService.clearValidityOverride(uri.asciiHost, uri.port);
        log("clearing cache");
        apd.log();
        delete responses[apd.toOverrideLabel()];
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
  getInvalidCert: function(uri) {
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

    log("certificate:");
    switch (cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer)) {
    case Ci.nsIX509Cert.VERIFIED_OK:
      log("\tSSL status: OK");
      break;
    case Ci.nsIX509Cert.NOT_VERIFIED_UNKNOWN:
      log("\tSSL status: not verfied/unknown");
      break;
    case Ci.nsIX509Cert.CERT_REVOKED:
      log("\tSSL status: revoked");
      break;
    case Ci.nsIX509Cert.CERT_EXPIRED:
      log("\tSSL status: expired");
      break;
    case Ci.nsIX509Cert.CERT_NOT_TRUSTED:
      log("\tSSL status: not trusted");
      break;
    case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED:
      log("\tSSL status: issuer not trusted");
      break;
    case Ci.nsIX509Cert.ISSUER_UNKNOWN:
      log("\tSSL status: issuer unknown");
      break;
    case Ci.nsIX509Cert.INVALID_CA:
      log("\tSSL status: invalid CA");
      break;
    default:
      log("\tSSL status: unexpected failure");
      break;
    }
    log("\tCommon Name: " + cert.commonName);
    log("\tOrganisation: " + cert.organization);
    log("\tIssuer: " + cert.issuerOrganization);
    log("\tSHA1 fingerprint: " + cert.sha1Fingerprint);

    var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
    log("\tValid from: " + validity.notBeforeGMT);
    log("\tValid until: " + validity.notAfterGMT);
  },

////////////////////////////////////////////////////////////
// CONTEXT MENU FUNCTIONS
////////////////////////////////////////////////////////////

  contextMenuFunctions: {

    clearSite: function() {
      var browser = gBrowser.selectedBrowser;
      var uri = browser.currentURI;
      try {
        var cert = browser.securityUI.SSLStatus.serverCert;
      } catch(e) {
        log("no valid cert found?");
        return;
      }
      var apd = monkeysphere.createAgentPostData(uri, cert);
      monkeysphere.overrides.clear(apd);
      // FIXME: why does the override seem to persist after a clear?
      if(!monkeysphere.overrides.certStatus(apd)) {
        alert('Monkeysphere: site clear error.  Is override cert cleared?');
      }
      var newstate = browser.monkeysphere.state;
      var newmessage = browser.monkeysphere.message + ' [NO LONGER CACHED]';
      monkeysphere.setStatus(browser, newstate, newmessage);
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
                    })();
