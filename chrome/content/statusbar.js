// Monkeysphere XUL extension
// Copyright © 2010 Jameson Rollins <jrollins@finestructure.net>
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

  clearSiteCache: function() {
    monkeysphere.cache.clear(gBrowser.currentURI);
  },

  certs: function() {
    openDialog("chrome://pippki/content/certManager.xul", "Certificate Manager");
  },

  help: function() {
    gBrowser.loadOneTab("chrome://monkeysphere/locale/help.html",
			null, null, null, false);
  }
};
