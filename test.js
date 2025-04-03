const http = require('http');
const https = require('https');
const {HttpsProxyAgent} = require('https-proxy-agent');
const { DOMParser } = require('xmldom');
const fs = require('fs');
const crypto = require('crypto');
const { createHash } = require('crypto');
const { SignedXml } = require('xml-crypto');
const path = require('path');

function getCertificate(descriptor) {
    return descriptor.getElementsByTagName('KeyDescriptor');
}

const xmlString = fs.readFileSync('metadata.xml', 'utf8').toString();

const xmlDoc = new DOMParser().parseFromString(xmlString, 'application/xml');

const entities = xmlDoc.getElementsByTagName('EntityDescriptor');

for(let i = 0; i < entities.length; i++){
    const entity = entities[i];
    const descriptor = entity.getElementsByTagName('SPSSODescriptor')[0];
    const body = getCertificate(descriptor);
    if(body.length === 2 && !body[0].getAttribute('use').includes('signing') && !body[0].getAttribute('use').includes('encryption') && !body[1].getAttribute('use').includes('signing') && !body[1].getAttribute('use').includes('encryption') && body[0].getElementsByTagName('ds:KeyName')[0].textContent === body[1].getElementsByTagName('ds:KeyName')[0].textContent && body[0].getElementsByTagName('ds:X509Certificate')[0].textContent !== body[1].getElementsByTagName('ds:X509Certificate')[0].textContent){
            const c1 = `-----BEGIN CERTIFICATE-----\n${body[0].getElementsByTagName('ds:X509Certificate')[0].textContent}\n-----END CERTIFICATE-----`;
            const cert1 = new crypto.X509Certificate(c1);
            const c2 = `-----BEGIN CERTIFICATE-----\n${body[1].getElementsByTagName('ds:X509Certificate')[0].textContent}\n-----END CERTIFICATE-----`;
            const cert2 = new crypto.X509Certificate(c2);
            console.log(entity.getAttribute('entityID'));

        }
}