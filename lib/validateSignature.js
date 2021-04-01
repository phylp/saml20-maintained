'use strict';

var select = require('xml-crypto').xpath;
var SignedXml = require('xml-crypto').SignedXml;
var Dom = require('xmldom').DOMParser;
var thumbprint = require('thumbprint');

// Only takes cert now; thumbprint not implemented
module.exports = function validateSignature(xml, cert, certThumbprint) {
  xml = xml.replace(/\r\n?/g, '\n');
  var doc = new Dom({}).parseFromString(xml);
  var signature = select(doc, '/*/*/*[local-name(.)=\'Signature\' and namespace-uri(.)=\'http://www.w3.org/2000/09/xmldsig#\']')[0]
    || select(doc, '/*/*[local-name(.)=\'Signature\' and namespace-uri(.)=\'http://www.w3.org/2000/09/xmldsig#\']')[0];
  var signed = new SignedXml();

  signed.keyInfoProvider = {
    file: "",
    getKeyInfo: function getKeyInfo () {
      return '<X509Data></X509Data>';
    },
    getKey: function getKey() {
      return certToPEM(cert);
    }
  }

  signed.loadSignature(signature);
  var valid = signed.checkSignature(xml);
  if (cert) {
    return valid
  }
};

function certToPEM(cert) {
  if (cert.indexOf('BEGIN CERTIFICATE') === -1 && cert.indexOf('END CERTIFICATE') === -1) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = '-----BEGIN CERTIFICATE-----\n' + cert;
    cert = cert + '\n-----END CERTIFICATE-----\n';
    return cert;
  } else {
    return cert;
  }
}
