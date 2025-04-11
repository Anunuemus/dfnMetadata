const https = require('https');
const {HttpsProxyAgent} = require('https-proxy-agent');
const { DOMParser } = require('xmldom');
const fs = require('fs');
const crypto = require('crypto');
const { SignedXml } = require('xml-crypto');
const path = require('path');

getMetadata();

/**
 * Fetches the metadata, writes it to metadata.xml and triggers processing.
 * @throws {Error} on bad config or fetching
 */
function getMetadata(){

    let json;

    try{
        json = JSON.parse(fs.readFileSync('config.json', 'utf8'));
    }catch(e){
        throw new Error(e);
    }
        

    const spMetadataUrl = json.spMetadataUrl;

    const webproxy = json.webproxy;
    //createJSON(json, webproxy);

    const agent = new HttpsProxyAgent(webproxy);
    const req = https.get(spMetadataUrl, {agent},  (res) => {
        const fileStream = fs.createWriteStream('metadata.xml');  

        fileStream.on('error', function(err) {
            throw err;
        });
    
        res.pipe(fileStream);
    
        fileStream.on('finish', () => {
            createJSON(json, webproxy);
        });
    });

    req.on('error', (err) => console.error('Error:', err));
    req.end();
}

/**
 * Creates JSON, .crt, .pub file for every SP to ./SPS respectively.
 * Validates signature of xml content using dfn-aai.pem.
 * Iterates over all entityDescriptors and creates files for all matches with config entries.
 * @param {JSON} json - Content of config.json.
 * @param {string} webproxy - For https requests.
 */
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

            if(!descriptorCheck(entity.getElementsByTagName('SPSSODescriptor'), match)){
                continue;
            }

            const descriptor = entity.getElementsByTagName('SPSSODescriptor')[0];

    
            const cert = getCertificate(descriptor);
            const publicKey = cert ? cert.publicKey.export({ type: 'spki', format: 'pem' }) : '';
            const logo = await getLogo(descriptor, webproxy);
            const assertionConsumerService = getAssertionConsumerService(descriptor);
            const info = getInfo(descriptor);
            const contacts = getContact(entity);
            const requestedAttributes = getRequestedAttributes(descriptor);

            if(!goCheck(match, cert, publicKey, logo, assertionConsumerService, info, contacts)){
                console.log(`No files created for ${match.name}.\n`);
                continue;
            }
    
            const results = {
                appl: match.name,
                issuer: match.entityID,
                url: info,
                logo: logo,
                protection_requirements: "normal",
                users: [],               
                saml_ecp: {
                    allowed: false,
                    service_accounts: [],
                    allowed_user: false,
                },
                groups: [],
                preferredAuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
                preferredNameidFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                singleLogoutService: "",
                logoutResponseUrl: "",
                assertionConsumerService: assertionConsumerService,
                addAttributeValueDefinition : true,
                sendErrorResponse: true,
                visible: true,
                secure: false,
                cert: `${match.name + '-' + certFileName}.crt`,
                pub: `${match.name + '-' + certFileName}.pub`,
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
    
                reqAttr: requestedAttributes,
                contacts : contacts
            };
            
            certStr = certStr.concat(cert.toString());
            pubKeyStr = pubKeyStr.concat(publicKey.toString());

            const jsonString = JSON.stringify(results, null, 2);

            writeFiles('SPs/', match, jsonString, certStr, pubKeyStr, certFileName);
        }
    }
    deleteFiles('SPs/', sp.map(entry => entry.name), certFileName);
}

/**
 * Writes all files for a given sp.
 * @param {string} dir - Directory to which files are written
 * @param {object} match - sp matching with config entry.
 * @param {string} jsonString - Content of sp specific json.
 * @param {string} certStr - Certificate of sp specific .crt.
 * @param {string} pubKeyStr - Public key of sp specific .pub.
 * @param {string} certFileName - Name of sp specific .crt and .pub.
 * @return on empty JSON content doing nothing
 * @throws {Error} on directory not found, failed write or rename
 */
function writeFiles(dir, match, jsonString, certStr, pubKeyStr, certFileName){

    if(jsonString === ''){
        console.error('JSON String is empty.');
        console.log(`No files created for ${match.name}`);
        return;
    }

    const hash = crypto.createHash('sha256');    
    hash.update(jsonString, 'utf8');
    const digest = hash.digest('hex');

    try{
        if(!fs.existsSync(dir)){
            fs.mkdirSync(dir);
        }

        let filenames = fs.readdirSync(dir);
        let file = filenames.find(file => file.includes(match.name));    
        let name = match.name.concat('-', digest)

        if(file){

            if(!file.includes(name)){

                fs.writeFileSync(dir.concat(file), jsonString);

                fs.renameSync(dir.concat(file), `${dir + name}-metadata.json`);
            
                fs.writeFileSync(`${dir + match.name + '-' + certFileName}.crt`, certStr);
            
                fs.writeFileSync(`${dir + match.name + '-' + certFileName}.pub`, pubKeyStr);
            }

        }else{

            fs.writeFileSync(`${dir + name}-metadata.json`, jsonString);

            fs.writeFileSync(`${dir + match.name + '-' + certFileName}.crt`, certStr);
            
            fs.writeFileSync(`${dir + match.name + '-' + certFileName}.pub`, pubKeyStr);
        }
    } catch (e) {
        throw new Error(e);
    }
}

/**
 * Deletes all files for all sp not listed in config file.
 * @param {string} dir - Directory from which files are deleted.
 * @param {string} names - Names of sp specified in config file.
 * @param {string} certFileName - Name of sp specific .crt and .pub.
 * @throws {Error} on directory not found or failed unlink
 */
function deleteFiles(dir, names, certFileName){

    const EXTENSION = '.json';
    let dirEntries;

    try{
        dirEntries = fs.readdirSync(dir)
    } catch (e) {
        throw new Error(e);
    }

    if(dirEntries.length === 0){
        console.log('No files found.');
    }

    const targetFiles = fs.readdirSync(dir).filter(file => {
        return path.extname(file) === EXTENSION;
    });

    targetFiles.forEach(file => {

        if(!names.some(name => file.includes(name))){

            try{
                fs.unlinkSync(dir.concat(file));

                const fileName = file.toString().split('-')[0];

                fs.unlinkSync(`${dir + fileName + '-' + certFileName}.crt`);

                fs.unlinkSync(`${dir + fileName + '-' + certFileName}.pub`);

            } catch (e) {
                throw new Error(e);
            }
        }
    });
    
}

/**
 * validates signature of xml content
 * @param {Document} xmlDoc - XML document to validate.
 * @param {string} xmlString - String of XML document.
 * @throws {Error} on bad signature or XML content.
 */
function validateSig(xmlDoc, xmlString){

    const node = xmlDoc.getElementsByTagName('ds:Signature')[0];
    
    const sig = new SignedXml({
        publicCert:  fs.readFileSync('dfn-aai.pem', 'utf8'),
        getCertFromKeyInfo: () => null,
    });
    sig.loadSignature(node);

    try{
        const isValid = sig.checkSignature(xmlString);
        if(!isValid){
            throw new Error('Bad Signature or metadata.');
        }
    }catch (e){
        console.error(e);
    }
}

/**
 * Retrieves the certificate body and creates a X509Certificate.
 * @param {Element} descriptor - XML element to process.
 * @return {X509Certificate|null} X509Certificate or null on invalid certificate
 */
function getCertificate(descriptor) {

    const body = descriptor.getElementsByTagName('ds:X509Certificate');
    let ret;

    if(body.length === 2 && !body[0].getAttribute('use').includes('signing') && !body[0].getAttribute('use').includes('encryption') && !body[1].getAttribute('use').includes('signing') && !body[1].getAttribute('use').includes('encryption') && descriptor.getElementsByTagName('ds:KeyName')[0].textContent === descriptor.getElementsByTagName('ds:KeyName')[0].textContent && body[0].textContent !== body[1].textContent){
        
        const c1 = `-----BEGIN CERTIFICATE-----\n${body[0].textContent}\n-----END CERTIFICATE-----`;
        const cert1 = new crypto.X509Certificate(c1);
        
        const c2 = `-----BEGIN CERTIFICATE-----\n${body[1].textContent}\n-----END CERTIFICATE-----`;
        const cert2 = new crypto.X509Certificate(c2);
        
        ret =  cert1.validToDate > cert2.validToDate ? cert1 : cert2;
    }else{
        const certificate = `-----BEGIN CERTIFICATE-----\n${body[0].textContent}\n-----END CERTIFICATE-----`;
        ret = new crypto.X509Certificate(certificate);
    }
    
    if(Date.parse(ret.validTo) < new Date().getTime()){
        console.error('Certificate is not valid anymore.');
        return null;
    }

    return ret;
}

/**
 * Fetches logo from url in descriptor and converts it to Base64-encoded data URI.
 * @async
 * @param {Element} descriptor - XML element to process.
 * @param {string} proxy - Proxy for https request.
 * @return {Promise<string>|''} Promise that resolves to a Base64-encoded data URI or empty string on empty logo element .
 */
async function getLogo(descriptor, proxy) {

    const logoElement = descriptor.getElementsByTagName('mdui:Logo')[0];

    if(!logoElement){
        return '';
    }
    
    const agent = new HttpsProxyAgent(proxy);
        
    return new Promise((resolve, reject) => {

        https.get(logoElement.textContent, { agent }, (resp) => {
                
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

/**
 * Gets Assertion Consumer Service of descriptor.
 * @param {Element} descriptor - XML element to process.
 * @return {string|null} Assertion Consumer Service of sp
 */
function getAssertionConsumerService(descriptor){
    const body = descriptor.getElementsByTagName('AssertionConsumerService')[0];
    return body.getAttribute("Location");
}

/**
 * Gets Information URL of descriptor.
 * @param {Element} descriptor - XML element to process.
 * @return {string|''} Information URL of sp or empty string
 */
function getInfo(descriptor){
    const body = descriptor.getElementsByTagName('mdui:InformationURL')[0];
    return body ? body.textContent : '';
}

/**
 * Gets contact information of sp.
 * @param {Element} entity - XML element to process.
 * @return {Array} Array with contact type and email
 */
function getContact(entity){
    const body = entity.getElementsByTagName('ContactPerson');
    return Array.from(body).map(contact => 
        [contact.getAttribute('contactType'), contact.getElementsByTagName('EmailAddress')[0].textContent.split(':')[1]]
    );
}

/**
 * Gets Requested Atributes of sp.
 * @param {Element} descriptor - XML element to process.
 * @return {Array} Array with all FriendlyNames of Requested Attributes
 */
function getRequestedAttributes(descriptor){

    const attributes = descriptor.getElementsByTagName('RequestedAttribute');
    const attributeArray = Array.from(attributes);

    return attributeArray.filter(attribute => 
        attribute.getAttribute("isRequired") === "true"
    ).map(attribute => 
        attribute.getAttribute("FriendlyName")
    );
}

/**
 * Checks if SPSSODescriptor is present.
 * @param {Element} descriptor - XML element to process.
 * @param {object} match - sp matching with config entry.
 * @return {boolean} true if SPSSODescriptor is present, false otherwise
 */
function descriptorCheck(descriptor, match){
    if(!descriptor[0]){
        console.error(`No SPSSODescriptor found for ${match.name}.`);
        console.log(`No files created for ${match.name}.\n`);
        return false;
    }
    return true;
}

/**
 * Checks if all JSON entries are valid and usable.
 * JSON, .crt and .pub are not written if anything is not valid or usable besides contact. 
 * @param {object} match - sp matching with config entry.
 * @param {X509Certificate} cert - Certificate of sp.
 * @param {string} publicKey - Public Key of sp.
 * @param {string} logo - Logo of sp.
 * @param {string} assertionConsumerService - Assertion Consumer Service of sp. 
 * @param {string} info - Information URL of sp.
 * @param {Array} contact - Contact Information of sp.
 * @return {boolean} True if all checks pass, false otherwise
 */
function goCheck(match, cert, publicKey, logo, assertionConsumerService, info, contact){
    if(!cert){
        console.error(`Invalid or no certificate found for ${match.name}.`);
        return false;
    }
    if(!publicKey){
        console.error(`No public key found for ${match.name}. You probably did something very wrong since this message shouldn't ever show.`);
        return false;
    }
    if(logo === ''){
        console.error(`No logo found for ${match.name}.`);
        return false;
    }
    if(!assertionConsumerService){
        console.error(`No assertion consumer service found for ${match.name}.`);
        return false;
    }
    if(!info){
        console.error(`No info/login found for ${match.name}.`);
        return false;
    }
    if(!contact){
        console.error(`No contact information found for ${match.name}. JSON will be created without contact.`);
    }
    return true;
}

module.exports = 
{ 
    getAssertionConsumerService, 
    getInfo, 
    getContact,
    getRequestedAttributes, 
    getLogo, descriptorCheck, 
    getCertificate, 
    writeFiles,
    deleteFiles 
};