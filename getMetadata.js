const https = require('https');
const {HttpsProxyAgent} = require('https-proxy-agent');
const { DOMParser } = require('xmldom');
const fs = require('fs');
const crypto = require('crypto');
const { createHash } = require('crypto');
const { SignedXml } = require('xml-crypto');
const path = require('path');

function writeFiles(match, jsonString, certStr, pubKeyStr, certFileName){

    const hash = createHash('sha256');    
    hash.update(jsonString, 'utf8');
    const digest = hash.digest('hex');

    if(!fs.existsSync('SPs')){
        fs.mkdirSync('SPs');
    }

    let fileames = fs.readdirSync('SPs');
    let file = fileames.find(file => file.includes(match.name));    
    let name = match.name.concat('-', digest)

    if(file){

        if(!file.includes(name)){

            fs.writeFileSync('SPs/'.concat(file), jsonString);

            fs.renameSync('SPs/'.concat(file), `SPs/${name}-metadata.json`);
        
            fs.writeFileSync(`SPs/${match.name + '-' + certFileName}.crt`, certStr);
        
            fs.writeFileSync(`SPs/${match.name + '-' + certFileName}.pub`, pubKeyStr);
        }

    }else{

        fs.writeFileSync(`SPs/${name}-metadata.json`, jsonString);

        fs.writeFileSync(`SPs/${match.name + '-' + certFileName}.crt`, certStr);
        
        fs.writeFileSync(`SPs/${match.name + '-' + certFileName}.pub`, pubKeyStr);
    }
}

function deleteFiles(names, certFileName){

    const EXTENSION = '.json';

    const targetFiles = fs.readdirSync('SPs').filter(file => {
        return path.extname(file) === EXTENSION;
    });

    targetFiles.forEach(file => {

        if(!names.some(name => file.includes(name))){

            fs.unlink('SPs/'.concat(file), (err) => {
                if (err) throw err;
            });

            const fileName = file.toString().split('-')[0];

            fs.unlink(`SPs/${fileName + '-' + certFileName}.crt`, (err) => {
                if (err) console.log(err);
            });

            fs.unlink(`SPs/${fileName + '-' + certFileName}.pub`, (err) => {
                if (err) console.log(err);
            });
        }
    });
    
}

function validateSig(xmlDoc, xmlString){

    const node = xmlDoc.getElementsByTagName('ds:Signature')[0];
    
    const sig = new SignedXml({
        publicCert:  fs.readFileSync('dfn-aai.pem', 'utf8'),
        getCertFromKeyInfo: () => null,
    });
    sig.loadSignature(node);

    try{
        const isValid = sig.checkSignature(xmlString.concat("test"));
        if(!isValid){
            throw new Error('Bad Signature or metadata.');
        }
    }catch (e){
        console.log(e);
    }
}

function getCertificate(descriptor) {

    const body = descriptor.getElementsByTagName('ds:X509Certificate');

    if(body.length === 2 && !body[0].getAttribute('use').includes('signing') && !body[0].getAttribute('use').includes('encryption') && !body[1].getAttribute('use').includes('signing') && !body[1].getAttribute('use').includes('encryption') && descriptor.getElementsByTagName('ds:KeyName')[0].textContent === descriptor.getElementsByTagName('ds:KeyName')[0].textContent && body[0].textContent !== body[1].textContent){
        
        const c1 = `-----BEGIN CERTIFICATE-----\n${body[0].textContent}\n-----END CERTIFICATE-----`;
        const cert1 = new crypto.X509Certificate(c1);
        
        const c2 = `-----BEGIN CERTIFICATE-----\n${body[1].textContent}\n-----END CERTIFICATE-----`;
        const cert2 = new crypto.X509Certificate(c2);
        
        const ret =  cert1.validToDate > cert2.validToDate ? cert1 : cert2;
        
        if(Date.parse(ret.validTo) < new Date().getTime()){
            throw new Error('Certificate is not valid anymore');
        }

        return ret;
    }

    const certificate = `-----BEGIN CERTIFICATE-----\n${body[0].textContent}\n-----END CERTIFICATE-----`;
    const ret = new crypto.X509Certificate(certificate);
    
    if(Date.parse(ret.validTo) < new Date().getTime()){
        throw new Error('Certificate is not valid anymore');
    }

    return ret;
}

async function getLogo(descriptor, proxy) {

    const logoElement = descriptor.getElementsByTagName('mdui:Logo')[0].textContent;
    
    if(logoElement){    
        const agent = new HttpsProxyAgent(proxy);
        
        return new Promise((resolve, reject) => {

            https.get(logoElement, { agent }, (resp) => {
                
                resp.setEncoding('base64');
                let body = "data:" + resp.headers["content-type"] + ";base64,";

                resp.on('data', (data) => {
                    body += data;
                });

                resp.on('end', () => {
                    resolve(body);
                });
            }).on('error', (e) => {
                reject(`Got error: ${e.message}`);
            });
        });
    }
    return "";
}

function getAssertionConsumerService(descriptor){
    const body = descriptor.getElementsByTagName('AssertionConsumerService')[0];
    return body.getAttribute("Location");
}

function getContact(entity){
    const body = entity.getElementsByTagName('ContactPerson');
    return Array.from(body).map(contact => 
        [contact.getAttribute('contactType'), contact.getElementsByTagName('EmailAddress')[0].textContent.split(':')[1]]
    );
}

function getRequestedAttributes(descriptor){

    const attributes = descriptor.getElementsByTagName('RequestedAttribute');
    const attributeArray = Array.from(attributes);

    return attributeArray.filter(attribute => 
        attribute.getAttribute("isRequired") === "true"
    ).map(attribute => 
        attribute.getAttribute("FriendlyName")
    );
}

async function createJSON(json, webproxy) {

    const sp = json.sp;
    const certFileName = json.certFileName;

    const xmlString = fs.readFileSync('metadata.xml', 'utf8').toString();

    const xmlDoc = new DOMParser().parseFromString(xmlString, 'application/xml');

    const entities = xmlDoc.getElementsByTagName('EntityDescriptor');

    validateSig(xmlDoc, xmlString);

    for (let i = 0; i < entities.length; i++) {

        const entity = entities[i];
        const entityID = entity.getAttribute('entityID');

        const match = sp.find(ID => entityID.includes(ID.entityID));
    
        if (match) {

            let certStr = "";
            let pubKeyStr = "";
            const descriptor = entity.getElementsByTagName('SPSSODescriptor')[0];
    
            const cert = getCertificate(descriptor);
            const publicKey = cert.publicKey.export({ type: 'spki', format: 'pem' });
            const logo = await getLogo(descriptor, webproxy);
            const assertionConsumerService = getAssertionConsumerService(descriptor);
            const contacts = getContact(entity);
            const requestedAttributes = getRequestedAttributes(descriptor);
    
            const results = {
                appl: match.name,
                issuer: match.entityID,
                url: "https://dummy.url:port",
                logoUrl: logo,
                protection_requirements: "normal",
                users: [],               
                saml_ecp: {
                    allowed: false,
                    service_accounts: [],
                    allowed_user: false,
                },
                groups: [],
                preferredAuthnContext: "urn:oasis:names:tc:SAML:2.0:ac: classes:Kerberos",
                preferredNameidFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                singleLogoutService: "",
                logoutResponseUrl: "",
                assertionConsumerService: assertionConsumerService,
                sendErrorResponse: true,
                visible: true,
                secure: false,
                cert: `./SPs/${match.name + '-' + certFileName}.crt`,
                pub: `./SPs/${match.name + '-' + certFileName}-dummy.pub`,
                oidcClient: {
                    client_id: "",
                    client_secret: "",
                    redirect_uris: [],
                    post_logout_redirect_uris: [],
                    backchannel_logout_uri: "",
                    backchannel_logout_session_required: true,
                    response_types: [],
                    grant_types: [],
                    token_endpoint_auth_method: "",
                    id_token_signed_response_alg: "",
                    pkce: true
                },
    
                //reqAttr: requestedAttributes
                //contacts : contacts
            };
            
            certStr = certStr.concat(cert.toString());
            pubKeyStr = pubKeyStr.concat(publicKey.toString());

            const jsonString = JSON.stringify(results, null, 2);

            writeFiles(match, jsonString, certStr, pubKeyStr, certFileName);
        }
    }
    deleteFiles(sp.map(entry => entry.name), certFileName);
}

function getMetadata(){

    const json = JSON.parse(fs.readFileSync('config.json', 'utf8'));

    const spMetadataUrl = json.spMetadataUrl;

    const webproxy = json.webproxy.toString();

    const agent = new HttpsProxyAgent(webproxy);
    const req = https.get(spMetadataUrl, {agent},  (res) => {
        const fileStream = fs.createWriteStream('metadata.xml');  
    
        res.pipe(fileStream);
    
        fileStream.on('finish', () => {
            createJSON(json, webproxy);
        });
    });

    req.on('error', (err) => console.error('Error:', err));
    req.end();
}

getMetadata();