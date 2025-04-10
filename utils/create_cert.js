var forge = require('node-forge');
const fs = require('fs');
const { create } = require('domain');
var pki = forge.pki;

function createCert(valid){
    var keys = pki.rsa.generateKeyPair(2048);

    var cert = pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    if(valid) cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);


    var attrs = [{
    name: 'commonName',
    value: 'localhost'
    }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    cert.sign(keys.privateKey);

    var pem = pki.certificateToPem(cert);
    var body = pem.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').trim();
    return body
}

module.exports = {createCert};