// Monkeysphere global namespace
var monkeysphere = {

  states: {
    ERR: -1,
    SEC: 0,
    INS: 1,
    NEU: 2
  },

  root_prefs: Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranchInternal),
  override_service: Components.classes["@mozilla.org/security/certoverride;1"].getService(Components.interfaces.nsICertOverrideService),

////////////////////////////////////////////////////////////
// LOG FUNCTIONS
////////////////////////////////////////////////////////////

  log: function(flag, line) {
    var log_all = true;

    var log_flags = {
      "policy" : false,
      "query" : false,
      "main" : false,
      "error" :  false
    };

    line = "monkeysphere: " + flag + ": " + line;
    try {
      if(!log_flags[flag] && !log_all)
	return;
      dump(line);
      try {
	// this line works in extensions
	Firebug.Console.log(line);
      } catch(e) {
	// ignore, this will blow up if Firebug is not installed
      }
      try {
	console.log(line); // this line works in HTML files
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

  // initialization function
  init: function() {
    monkeysphere.log("main", "begin initialization");
    monkeysphere.setStatus(null, monkeysphere.states.NEU, "");
    monkeysphere.messages = document.getElementById("message_strings");
    getBrowser().addProgressListener(monkeysphere.listener,
				     Components.interfaces.nsIWebProgress.NOTIFY_STATE_DOCUMENT);
    // FIXME: do we need this?  what is it for?
    //setTimeout(function (){ requeryAllTabs(gBrowser); }, 4000);
    monkeysphere.log("main", "initialization complete");
  },

////////////////////////////////////////////////////////////
// STATUS FUNCTIONS
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
	monkeysphere.log("main", "set status: secure\n");
	i.setAttribute("src", "chrome://monkeysphere/content/good.png");
	break;
      case monkeysphere.states.INS:
	monkeysphere.log("main", "set status: unsecure\n");
	i.setAttribute("src", "chrome://monkeysphere/content/bad.png");
	break;
      case monkeysphere.states.NEU:
	monkeysphere.log("main", "set status: neutral\n");
	i.setAttribute("src", "chrome://monkeysphere/content/default.png");
	break;
      case monkeysphere.states.ERR:
	monkeysphere.log("main", "set status: error\n");
	i.setAttribute("src", "chrome://monkeysphere/content/error.png");
	break;
    }
    monkeysphere.log("main", "tooltip: " + tooltip + "\n");
  },

  // create the event listener object
  listener: {
    onLocationChange:
      function(aWebProgress, aRequest, aURI) {
	try {
	  monkeysphere.log("main", "listener: location change: " + aURI.spec);
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

  // FIXME: what is this functions for?  why do we need it?
  requeryAllTabs: function(b) {
    var num = b.browsers.length;
    for (var i = 0; i < num; i++) {
      var browser = b.getBrowserAtIndex(i);
      updateStatus(browser, false);
    }
  },

  // Updates the status of the current page
  // 'has_user_permission' indicates whether the user
  // explicitly pressed a button to launch this query,
  // by default this is not the case
  updateStatus: function(browser, has_user_permission) {
    if(!browser) {
      monkeysphere.log("error", "no browser!?!");
      return;
    }
    var uri = browser.currentURI;
    if(!uri) {
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getString("statusNoData"));
      return;
    }

    monkeysphere.log("main", "updating status: " + uri.spec);

    // check uri host
    try {
      var ignore = uri.host;
    } catch(err) {
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getFormattedString("statusURLNotValid"));
      return;
    }
    if(!uri.host) {
      monkeysphere.log("main", "uri host empty");
      return;
    }

    // test for https
    monkeysphere.log("main", "uri scheme: " + uri.scheme);
    if(uri.scheme != "https") {
      monkeysphere.log("main", "uri scheme not https. ignoring");
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getFormattedString("statusNonHTTPS",
								      [uri.scheme]));
      return;
    }

    monkeysphere.log("main", "retrieving site certificate");

    // create tab info array
    var tab_info = {};
    tab_info.broken = false;
    tab_info.cert = monkeysphere.getCertificate(browser);

    // check site certificate
    if(!tab_info.cert) {
      setStatus(uri,
      monkeysphere.states.ERR,
      monkeysphere.messages.getFormattedString("statusNoCert",
					       [uri.host]));
      return;
    }
    var sha1 = tab_info.cert.sha1Fingerprint;
    var state = browser.securityUI.state;
    monkeysphere.log("main", "cert: md5: " + sha1 + ", state: " + state);

    tab_info.is_override_cert = monkeysphere.override_service.isCertUsedForOverrides(tab_info.cert, true, true);
    monkeysphere.log("main", "is_override_cert = " + tab_info.is_override_cert);
    var check_good = monkeysphere.root_prefs.getBoolPref("monkeysphere.check_good_certificates");

    if(state && Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) {
      monkeysphere.log("main", "clearing existing permission banners");
      monkeysphere.notify.clear(browser, "Monkeysphere-Permission");
    }

    // see if the browser has this cert installed prior to this browser session
    tab_info.already_trusted =
      (state & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE)
      && !(tab_info.is_override_cert);

    if(tab_info.already_trusted) {
      monkeysphere.log("main", "site cert already trusted by browser");
      if(!check_good) {
	monkeysphere.log("main", "preferences don't require check");
	monkeysphere.setStatus(uri,
			       monkeysphere.states.NEU,
			       monkeysphere.messages.getString("statusNoQueryRequested"));
	return;
      }
    }
    if(!tab_info.is_override_cert
       && state
       && Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE) {
      monkeysphere.log("main", "state is INSECURE, override required");
      tab_info.broken = true;
    }

    // check if user permission required
    var needs_perm = monkeysphere.root_prefs.getBoolPref("monkeysphere.require_user_permission");
    if(needs_perm && !has_user_permission) {
      monkeysphere.log("main", "user permission required");
      // NOTE: this function potentially calls the calling function!
      monkeysphere.notify.needsPermission(browser);
      monkeysphere.setStatus(uri,
			     monkeysphere.states.NEU,
			     monkeysphere.messages.getString("statusNeedsPermission"));
      return;
    }

    // query the agent
    monkeysphere.log("main", "querying validation agent");
    var agent_result = monkeysphere.queryAgent(tab_info.cert, uri, browser);
    if(!agent_result) {
      monkeysphere.log("error", "validation agent error");
      monkeysphere.notify.agentProblem(browser);
      monkeysphere.setStatus(uri,
			     monkeysphere.states.ERR,
			     monkeysphere.messages.getString("agentError"));
      return;
    }
  },

  // query the validation agent
  queryAgent: function(cert, uri) {
    monkeysphere.log("main", "query: " + uri);
    monkeysphere.log("main", "query: " + cert);

    return null;
  },

////////////////////////////////////////////////////////////
// CERT FUNCTIONS
////////////////////////////////////////////////////////////

  getCertificate: function(browser) {
    var cert = monkeysphere.getValidCert(browser.securityUI);
    if(!cert)
      cert = monkeysphere.getInvalidCert(browser.currentURI);
    if(!cert)
      return null;
    return cert;
  },

  // gets current certificate, if it PASSED the browser check
  getValidCert: function(ui) {
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

  // gets current certificat, if it FAILED the security check
  getInvalidCert: function(uri) {
    var recentCertsSvc =
      Components.classes["@mozilla.org/security/recentbadcerts;1"]
      .getService(Components.interfaces.nsIRecentBadCertsService);
    if (!recentCertsSvc)
      return null;

    var port = uri.port;
    if(port == -1)
      port = 443;

    var hostWithPort = uri.host + ":" + port;
    var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
    if (!gSSLStatus)
      return null;

    return gSSLStatus.QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
  },

////////////////////////////////////////////////////////////
// NOTIFICATION FUNCTIONS
////////////////////////////////////////////////////////////

  notify: {
    // clear notification
    clear: function(browser, value) {
      try {
	try{
	  var notificationBox = browser.getNotificationBox();
	} catch(e){
	  return;
	}
	var oldNotification =
	  notificationBox.getNotificationWithValue(value);
	if(oldNotification != null)
	  notificationBox.removeNotification(oldNotification);
      } catch (err) {
	monkeysphere.log("error","clearNotification error: " + err);
      }
    },

    // this is the drop down which is shown if preferences indicate
    // that queries require user permission
    needsPermission: function(browser) {
      var notificationBox = browser.getNotificationBox();

      monkeysphere.notify.clear(browser, "Monkeysphere");

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
      notificationBox.appendNotification(message, "Monkeysphere",
					 null, priority, buttons);
    },

    // this is the drop down which is shown if there
    // is a problem with the validation agent
    agentProblem: function(browser) {
      var notificationBox = browser.getNotificationBox();

      monkeysphere.notify.clear(browser, "Monkeysphere");

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
      notificationBox.appendNotification(message, "Monkeysphere", null,
					 priority, buttons);
    },

    // override a verification success with a monkeyspehre query
    override: function(browser) {
      var notificationBox = browser.getNotificationBox();

      monkeysphere.notify.clear(browser, "Monkeysphere");

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
      notificationBox.appendNotification(message, "Monkeysphere",
					 null, priority, buttons);
    },

    // alert to failure to verify host
    failed: function(browser) {
      var notificationBox = browser.getNotificationBox();

      monkeysphere.notifiy.clear(browser, "Monkeysphere");

      var message = monkeysphere.messages.getString("unableToVerify");
      var priority = notificationBox.PRIORITY_CRITICAL_LOW;
      var buttons = null;

      notificationBox.appendNotification(message, "Monkeysphere",
					 null, priority, buttons);
    }
  }

};
