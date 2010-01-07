// Monkeysphere global namespace
var monkeysphere = {

  states: {
    ERR: -1,
    SEC: 0,
    INS: 1,
    NEU: 2
  },

  // get extension preferences
  preferences: Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranchInternal),

  // override service class
  override: Components.classes["@mozilla.org/security/certoverride;1"].getService(Components.interfaces.nsICertOverrideService),

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

////////////////////////////////////////////////////////////
// INITIALIZATION
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // initialization function
  init: function() {
    monkeysphere.log("main", "-- begin initialization --");
    monkeysphere.setStatus(null, monkeysphere.states.NEU, "");
    monkeysphere.messages = document.getElementById("message_strings");
    getBrowser().addProgressListener(monkeysphere.listener,
				     Components.interfaces.nsIWebProgress.NOTIFY_STATE_DOCUMENT);
    // FIXME: do we need this?  what is it for?
    //setTimeout(function (){ requeryAllTabs(gBrowser); }, 4000);
    monkeysphere.log("main", "-- initialization complete --");
  },

  ////////////////////////////////////////////////////////////
  // FIXME: what is this functions for?  why do we need it?
  requeryAllTabs: function(b) {
    var num = b.browsers.length;
    for (var i = 0; i < num; i++) {
      var browser = b.getBrowserAtIndex(i);
      monkeysphere.updateStatus(browser, false);
    }
  },

////////////////////////////////////////////////////////////
// EVENT LISTENER
////////////////////////////////////////////////////////////

  listener: {
    onLocationChange:
      function(aWebProgress, aRequest, aURI) {
	monkeysphere.log("main", "listener: location change: " + aURI.spec);
	try {
	  monkeysphere.updateStatus(gBrowser, false);
	} catch(err) {
	  monkeysphere.log("error", "listener: location change: " + err);
	  monkeysphere.setStatus(aURI,
				 monkeysphere.states.ERR,
				 monkeysphere.messages.getFormattedString("internalError",
									  [err]));
	}
      },
    onStateChange:
      function(aWebProgress, aRequest, aFlag, aStatus) {
	var uri = gBrowser.currentURI;
	monkeysphere.log("main", "listener: state change " + uri.spec);
	if(!aFlag || !Components.interfaces.nsIWebProgressListener.STATE_STOP)
	  return;
	try {
	  monkeysphere.updateStatus(gBrowser, false);
	} catch (err) {
	  monkeysphere.log("error", "listener: state change: " + err);
	  monkeysphere.setStatus(uri,
				 monkeysphere.states.ERR,
				 monkeysphere.messages.getFormattedString("internalError",
									  [err]));
	}
      },
    onSecurityChange: function() { }, // FIXME: should we be looking at this too?
    onStatusChange: function() { },
    onProgressChange: function() { },
    onLinkIconAvailable: function() { }
  },

////////////////////////////////////////////////////////////
// STATUS FUNCTION
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // set the status
  setStatus: function(uri,state, tooltip) {
    if(uri != null && uri != window.gBrowser.currentURI) {
      monkeysphere.log("error","setStatus: uri missing");
      return;
    }
    if(!tooltip) {
      tooltip = "Monkeysphere";
    }

    var i = document.getElementById("monkeysphere-status-image");
    var t = document.getElementById("monkeysphere-status");

    // the following happens when called from a dialog
    if(!t || !i) {
      i = window.opener.document.getElementById("monkeysphere-status-image");
      t = window.opener.document.getElementById("monkeysphere-status");
    }

    t.setAttribute("tooltiptext", tooltip);
    switch(state){
      case monkeysphere.states.SEC:
	monkeysphere.log("main", "set status: secure");
	i.setAttribute("src", "chrome://monkeysphere/content/good.png");
	break;
      case monkeysphere.states.INS:
	monkeysphere.log("main", "set status: unsecure");
	i.setAttribute("src", "chrome://monkeysphere/content/bad.png");
	break;
      case monkeysphere.states.NEU:
	monkeysphere.log("main", "set status: neutral");
	i.setAttribute("src", "chrome://monkeysphere/content/default.png");
	break;
      case monkeysphere.states.ERR:
	monkeysphere.log("main", "set status: error");
	i.setAttribute("src", "chrome://monkeysphere/content/error.png");
	break;
    }
    monkeysphere.log("main", "tooltip: " + tooltip);
  },

////////////////////////////////////////////////////////////
// UPDATE AND QUERY FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // Updates the status of the current page
  // 'has_user_permission' indicates whether the user
  // explicitly pressed a button to launch this query,
  // by default this is not the case
  updateStatus: function(browser, has_user_permission) {
    monkeysphere.log("main", "==== updating status ====");

    if(!browser) {
      monkeysphere.log("error", "no browser!?!");
      return;
    }

    // check uri
    var uri = browser.currentURI;
    monkeysphere.log("main", "checking uri:");
    if(uri) {
      monkeysphere.log("main", " uri: " + uri.spec);
    } else {
      monkeysphere.log("main", " no uri data available");
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getString("statusNoData"));
      return;
    }

    // check host
    monkeysphere.log("main", "checking host:");
    try {
      monkeysphere.log("main", " host: " + uri.host);
    } catch(err) {
      monkeysphere.log("main", " host not valid");
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getString("statusURLNotValid"));
      return;
    }
    if(!uri.host) {
      monkeysphere.log("main", " host empty");
      return;
    }

    // test for https
    monkeysphere.log("main", "checking uri scheme: " + uri.scheme);
    if(uri.scheme != "https") {
      monkeysphere.log("main", " uri scheme not https. ignoring");
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getFormattedString("statusNonHTTPS",
								      [uri.scheme]));
      return;
    } else {
      monkeysphere.log("main", " scheme https. checking");
    }

    // check if exception has already been granted this session
    monkeysphere.log("main", "checking override status:");
    if(monkeysphere.getOverrideStatus(uri)) {
      monkeysphere.log("main", " site already validated");
      monkeysphere.setStatus(uri,
			     monkeysphere.states.SEC,
			     monkeysphere.messages.getString("statusValidated"));
      return;
    } else {
      monkeysphere.log("main", " site not validated");
    }

    // get site certificate
    monkeysphere.log("main", "retrieving site certificate:");
    var cert = monkeysphere.getCertificate(browser);
    if(!cert) {
      monkeysphere.setStatus(uri,
			     monkeysphere.states.ERR,
			     monkeysphere.messages.getFormattedString("statusNoCert",
								      [uri.host]));
      return;
    }
    var sha1 = cert.sha1Fingerprint;
    monkeysphere.log("main", " cert sha1: " + sha1);

    // check browser state
    monkeysphere.log("main", "checking security state:");
    var state = browser.securityUI.state;
    monkeysphere.log("main", " state: " + state);

    // if site secure, return
    if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
      monkeysphere.log("main", " site cert already trusted by browser");
      // and force check not set
      if(!monkeysphere.preferences.getBoolPref("monkeysphere.check_good_certificates")) {
	monkeysphere.log("main", "preferences don't require check");
	monkeysphere.setStatus(uri,
			       monkeysphere.states.NEU,
			       monkeysphere.messages.getString("statusAlreadyValid"));
	return;
      }
    // if site insecure continue
    } else if(state & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE) {
      monkeysphere.log("main", " state INSECURE: override required");
    // else, unknown state
    } else {
      monkeysphere.log("main", " state UNKNOWN");
    }

    // check if user permission required.  if so, call notification and return
    if(monkeysphere.preferences.getBoolPref("monkeysphere.require_user_permission")
       && !has_user_permission) {
      monkeysphere.log("main", "user permission required");
      monkeysphere.notify.needsPermission(browser);
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getString("statusNeedsPermission"));
      return;
    }

    // finally go ahead and query the agent
    monkeysphere.log("main", "querying validation agent:");
    monkeysphere.queryAgent(browser, cert);
  },

  ////////////////////////////////////////////////////////////
  // query the validation agent
  queryAgent: function(browser, cert) {
    var uri = browser.currentURI;

    var certLength = {};
    var certData = {};

    // get certificate info
    cert.getRawDER(certLength, certData);

    var agentURL = "http://localhost:8901/reviewcert";
    monkeysphere.log("query", "agentURL: " + agentURL);

    // "agent post data"
    var apd = {
      context: "https",
      uid: uri.host,
      pkc: {
	type: "x509der",
	data: certData
      }
    };
    // make JSON query string
    var query = JSON.stringify(apd);

    monkeysphere.log("query", " context: " + apd.context);
    monkeysphere.log("query", " uid: " + apd.uid);
    monkeysphere.log("query", " pkc.type: " + apd.pkc.type);
    monkeysphere.log("query", " pkc.data: " + apd.pkc.data);

    monkeysphere.log("query", "creating http request to " + agentURL);
    var client = new XMLHttpRequest();
    client.open("POST", agentURL, true);

    monkeysphere.log("query", "sending query: " + query);
    client.setRequestHeader("Content-type", "application/json");
    client.setRequestHeader("Content-length", query.length);
    client.setRequestHeader("Connection", "close");

    // setup the state change function
    client.onreadystatechange = function() {
      monkeysphere.onAgentStateChange(client, browser, cert);
    };

    client.send(query);
    monkeysphere.log("query", "query sent");
  },

  ////////////////////////////////////////////////////////////
  // when the XMLHttpRequest to the agent state changes
  onAgentStateChange: function(client, browser, cert) {
    monkeysphere.log("query", "state change: " + client.readyState);
    monkeysphere.log("query", " status: " + client.status);
    monkeysphere.log("query", " response: " + client.responseText);

    if (client.readyState == 4) {
      if (client.status == 200) {
	monkeysphere.securityOverride(browser, cert);
      }
    }
  },

////////////////////////////////////////////////////////////
// OVERRIDE FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  // get current validity override status
  getOverrideStatus: function(uri) {
    // the status return is a bool, true for override set
    var status;
    var aHashAlg = {};
    var aFingerprint = {};
    var aOverrideBits = {};
    var aIsTemporary = {};
    monkeysphere.log("debug", "current override state:");
    status = monkeysphere.override.getValidityOverride(uri.asciiHost, uri.port,
						       aHashAlg,
						       aFingerprint,
						       aOverrideBits,
						       aIsTemporary);
    monkeysphere.log("debug", "  " + status);
    monkeysphere.log("debug", "  " + JSON.stringify(aFingerprint));
    monkeysphere.log("debug", "  " + JSON.stringify(aOverrideBits));
    monkeysphere.log("debug", "  " + JSON.stringify(aIsTemporary));
    return status;
  },

  ////////////////////////////////////////////////////////////
  // browser security override function
  securityOverride: function(browser, cert) {
    monkeysphere.log("policy", "*** CERT SECURITY OVERRIDE REQUESTED ***");

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
    monkeysphere.getOverrideStatus(uri);

    monkeysphere.log("policy", "setting temporary override");
    monkeysphere.override.rememberValidityOverride(uri.asciiHost, uri.port,
						   cert,
						   overrideBits,
						   true);

    // check override status
    monkeysphere.getOverrideStatus(uri);

    monkeysphere.log("policy", "browser reload");
    // FIXME: why the "timeout"?  what's it for?
    setTimeout(
      function() {
	browser.loadURI(uri.spec);
      },
      25);

    // monkeyspherize favicon text
    monkeysphere.setFaviconText(monkeysphere.getFaviconText()
				+ "\n\n"
				+ "Monkeysphere validated");
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
	return null;
      }
    }
    return cert;
  },

  ////////////////////////////////////////////////////////////
  // gets current certificate, if it PASSED the browser check
  getValidCert: function(browser) {
    var ui = browser.securityUI;
    try {
      ui.QueryInterface(Components.interfaces.nsISSLStatusProvider);
      if(!ui.SSLStatus)
	return null;
      return ui.SSLStatus.serverCert;
    } catch (e) {
      monkeysphere.log("error", e);
      return null;
    }
  },

  ////////////////////////////////////////////////////////////
  getInvalidCert: function(browser) {
    try {
      var ssl_status = monkeysphere.getInvalidCertSSLStatus(browser.currentURI);
      return ssl_status.QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
    } catch(e) {
      return null;
    }
  },

  ////////////////////////////////////////////////////////////
  // gets current certificat, if it FAILED the security check
  getInvalidCertSSLStatus: function(uri) {
    var recentCertsService =
      Components.classes["@mozilla.org/security/recentbadcerts;1"]
      .getService(Components.interfaces.nsIRecentBadCertsService);
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

////////////////////////////////////////////////////////////
// NOTIFICATION FUNCTIONS
////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////
  notify: {

    /////////////////////////////////////////////////////////
    // return true and log if a given notification box is present
    checkPresent: function(browser, value) {
      if (browser.getNotificationBox().getNotificationWithValue(value)) {
	monkeysphere.log("main", "notification " + name + " already present");
	return true;
      }
      return false;
    },

    /////////////////////////////////////////////////////////
    // this is the drop down which is shown if preferences indicate
    // that queries require user permission
    needsPermission: function(browser) {
      var notificationBox = browser.getNotificationBox();

      var value = "Monkeysphere:Permission";

      if (monkeysphere.notify.checkPresent(browser,value))
	return;

      var message = monkeysphere.messages.getString("needsPermission");
      var priority = notificationBox.PRIORITY_WARNING_HIGH;
      var buttons = [
	{
	  label: monkeysphere.messages.getString("yesQuery"),
	  accessKey : "",
	  callback: function() {
	    // FIXME: this might be a problem if there are other notifications,
	    // but I can't figure out how to make it go away cleanly at startup
	    notificationBox.removeAllNotifications();

	    // update status
	    monkeysphere.log("main", "user gives query permission");
	    var uri = browser.currentURI;
	    monkeysphere.updateStatus(browser,true);
	  }
	},
	{
	  label: monkeysphere.messages.getString("learnMore"),
	  accessKey : "",
	  callback: function() {
	    browser.loadOneTab("chrome://monkeysphere/locale/help.html",
			       null, null, null, false);
	  }
	}
      ];
      notificationBox.appendNotification(message, value, null, priority, buttons);
    },

    /////////////////////////////////////////////////////////
    // this is the drop down which is shown if there
    // is a problem with the validation agent
    agentProblem: function(browser) {
      var notificationBox = browser.getNotificationBox();

      var value = "Monkeysphere:AgentProblem";

      var message = monkeysphere.messages.getString("agentError");
      var priority = notificationBox.PRIORITY_CRITICAL_LOW;
      var buttons = [
	{
	  label: "help",
	  accessKey : "",
	  callback: function() {
	    browser.loadOneTab("chrome://monkeysphere/locale/help.html",
			       null, null, null, false);
	  }
	}
      ];
      notificationBox.appendNotification(message, value, null, priority, buttons);
    },

    ////////////////////////////////////////////////////////
    // override verification success notification
    override: function(browser) {
      var notificationBox = browser.getNotificationBox();

      var value = "Monkeysphere:Override";

      var message = monkeysphere.messages.getString("verificationSuccess");
      var priority = notificationBox.PRIORITY_INFO_LOW;
      var buttons = [
	{
	  label: monkeysphere.messages.getString("learnMore"),
	  accessKey : "",
	  callback: function() {
	    browser.loadOneTab("chrome://monkeysphere/locale/help.html",
			       null, null, null, false);
	  }
	}
      ];
      notificationBox.appendNotification(message, value, null, priority, buttons);
    },

    ////////////////////////////////////////////////////////
    // alert to failure to verify host
    failed: function(browser) {
      var notificationBox = browser.getNotificationBox();

      var value = "Monkeysphere:Failed";

      var message = monkeysphere.messages.getString("unableToVerify");
      var priority = notificationBox.PRIORITY_CRITICAL_LOW;
      var buttons = null;

      notificationBox.appendNotification(message, value, null, priority, buttons);
    }
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
  }
};
