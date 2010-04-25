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

var EXPORTED_SYMBOLS = [
                        "agent_socket",
                        "log",
                        "getInvalidCert",
                        "overrides"
                       ];

  // select agent URL from environment variable or explicitly-set preference.
  // "http://localhost:8901" <-- NO TRAILING SLASH
  var agent_socket = function() {
    var envvar = "MONKEYSPHERE_VALIDATION_AGENT_SOCKET";;
    try {
      envvar = prefs.getCharPref("validation_agent_socket_environment_variable");
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
        ret = prefs.getCharPref("default_socket");
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

  ////////////////////////////////////////////////////////////
  // CERT FUNCTIONS
  ////////////////////////////////////////////////////////////

  // certificate override service class
  // http://www.oxymoronical.com/experiments/xpcomref/applications/Firefox/3.5/interfaces/nsICertOverrideService
  var certOverrideService = Components.classes["@mozilla.org/security/certoverride;1"].getService(Components.interfaces.nsICertOverrideService);

  //////////////////////////////////////////////////////////
  // FWIW, aWebProgress listener has:
  // securityUI = [xpconnect wrapped (nsISupports, nsISecureBrowserUI, nsISSLStatusProvider)]
  // but i don't think it can be used because it doesn't hold invalid cert info
  // FIXME: is there a better way to get the cert for the actual current connection?
  var getInvalidCert = function(uri) {
    try {
      var cert = getInvalidCertSSLStatus(uri).QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
      printCertInfo(cert);
      return cert;
    } catch(e) {
      return null;
    }
  };

  //////////////////////////////////////////////////////////
  // gets current ssl status info
  // http://www.oxymoronical.com/experiments/apidocs/interface/nsIRecentBadCertsService
  var getInvalidCertSSLStatus = function(uri) {
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
  };

  //////////////////////////////////////////////////////////
  // Print SSL certificate details
  // https://developer.mozilla.org/En/How_to_check_the_security_state_of_an_XMLHTTPRequest_over_SSL
  var printCertInfo = function(cert) {
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
  };

  ////////////////////////////////////////////////////////////
  // OVERRIDE CACHE OBJECT
  ////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////
  // object to store and retrieve data about monkeysphere status for sites
  // uses string of apd as key, and agent response as data
  var overrides = (function() {

    // response cache object
    var responses = {};

    return {

      // set override
      set: function(apd, agentResponse) {
        log("**** SET OVERRIDE ****");

        var uri = apd.uri;
        var cert = apd.cert;

        var SSLStatus = getInvalidCertSSLStatus(uri);
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
  })();
