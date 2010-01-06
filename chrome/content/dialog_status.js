var root_prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);

monkeysphere.status.form = function() {
  var sel = document.getElementById("info-radio").selectedIndex;
  document.getElementById("monkeysphere-svg-box").hidden = sel;
  document.getElementById("monkeysphere-description").hidden = !sel;
}

// returns a string that describes whether monkeysphere installed a security exception
monkeysphere.status.actionStr = function(uri,ti) {
 if(uri.scheme != "https")
   return "Monkeysphere only queries 'https' sites. This site uses '" + uri.scheme + "'.";
 if(ti.is_override_cert && ti.already_trusted)
   return "Monkeysphere has previously installed a security exception for this site.";
 if(ti.already_trusted)
   return "The browser trusts this site and requires no security exception.";
 if(ti.is_override_cert && ti.notary_valid && ti.exceptions_enabled && ti.isTemp)
   return "Monkeysphere installed a temporary security exception for this site.";
 if(ti.is_override_cert && ti.notary_valid && ti.exceptions_enabled && !ti.isTemp)
   return "Monkeysphere installed a permanent security exception for this site.";
 return "No security exception has been installed.";
};

monkeysphere.status.load = function() {
  try {
    var info = document.getElementById("monkeysphere-description");
    var host = document.getElementById("monkeysphere-information-caption");

    if(!window.opener) {
      log("error", "window.opener is null in results dialog");
      return;
      }
      var uri = window.opener.gBrowser.currentURI;
      if(!uri) {
	log("error", "null URI in results dialog");
      return;
    }
    try {
      var ignore = uri.host;
    } catch(e) {
      return;
    }

    var other_cache = window.opener.other_cache;
    var cert = window.opener.ssl_cache[uri.host];
    var ti = window.opener.tab_info_cache[uri.spec];
    host.label = uri.host;
    if(ti) {
      host.label += ": " + getActionStr(uri, ti);
    }
    if(cert){
      info.value  = cert.summary;
      liner.value = cert.tooltip;
      if(cert.svg && cert.svg != ""){
      	info.hidden = true;
      	var radio = document.getElementById("info-radio");
      	radio.hidden=false;
      	radio.selectedIndex = 0;
      }
    } else if (other_cache["reason"]) {
      info.value = other_cache["reason"];
    }
  } catch(e) {
    var text = "error loading results dialog: " + e;
    log("error", text);
    alert(text);
  }
  return true;
};
