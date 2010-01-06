// note: when debugging, it is useful to open this dialogs as
// windows for firebug console, etc

monkeysphere.dialog = {
  status: function() {
    window.openDialog(
    //window.open( // for debug
      "chrome://monkeysphere/content/dialog_status.xul",
      //"monkeysphereResults", "").focus();  // for debug
      "monkeysphereResults", "centerscreen, chrome, toolbar").focus();
  },

  prefs: function() {
    window.openDialog(
    //window.open( // for debug
      "chrome://monkeysphere/content/dialog_prefs.xul",
      //"monkeysphereResults", "").focus();  // for debug
      "monkeysphereResults", "centerscreen, chrome, toolbar").focus();
  },

  certs: function() {
    openDialog("chrome://pippki/content/certManager.xul", "Certificate Manager");
  },

  help: function() {
    gBrowser.loadOneTab("chrome://monkeysphere/locale/help.html",
			null, null, null, false);
    // openDialog("chrome://monkeysphere/locale/help.html",
    // 	     "",
    // 	     "width=600,height=600,resizable=yes");
  },
};
