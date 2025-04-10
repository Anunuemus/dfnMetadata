const fs = require('fs');
const crypto = require('crypto');
var assert = require('assert');
const { DOMParser } = require('xmldom');

const { getAssertionConsumerService, getInfo, getContact, getRequestedAttributes, getLogo, descriptorCheck, getCertificate, writeFiles, deleteFiles } = require('../getMetadata');
const { createCert } = require('../utils/create_cert');
const webproxy = JSON.parse(fs.readFileSync('config.json', 'utf8')).webproxy;

const goodCertBody = createCert(true);

const badCertBody = createCert(false);

const goodCert = new crypto.X509Certificate(`-----BEGIN CERTIFICATE-----\n${goodCertBody}\n-----END CERTIFICATE-----`);

const goodXML = `
<EntityDescriptor>
    <EntityDescriptor entityID = "tester">
        <SPSSODescriptor>
            <Extensions>
                <mdui:UIInfo>
                    <mdui:InformationURL>https://information.url</mdui:InformationURL>
                    <mdui:Logo>https://placehold.co/10/png</mdui:Logo>
                </mdui:UIInfo>
            </Extensions>
            <KeyDescriptor>
                <ds:KeyInfo>
                <ds:KeyName>testKey</ds:KeyName>
                    <ds:X509Data>
                        <ds:X509SubjectName>CN=localhost</ds:X509SubjectName>
                        <ds:X509Certificate>${goodCertBody}</ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </KeyDescriptor>
            <AssertionConsumerService Binding="binder" Location="Assertion Consumer Service" index="1"/>
            <AttributeConsumingService>
                <RequestedAttribute FriendlyName="required" isRequired="true"/>
                <RequestedAttribute FriendlyName="notRequired" isRequired="false"/>
            </AttributeConsumingService>
        </SPSSODescriptor>
        <ContactPerson contactType = "other">
            <EmailAddress>mailto:contact@email.com</EmailAddress>
        </ContactPerson>
    </EntityDescriptor>
</EntityDescriptor>
`;

const badXML = `
<EntityDescriptor>
    <EntityDescriptor entityID = "tester">
        <SPSSODescriptor>
            <Extensions>
                <mdui:UIInfo>
                </mdui:UIInfo>
            </Extensions>
            <KeyDescriptor>
                <ds:KeyInfo>
                <ds:KeyName>testKey</ds:KeyName>
                    <ds:X509Data>
                        <ds:X509SubjectName>CN=localhost</ds:X509SubjectName>
                        <ds:X509Certificate>${badCertBody}</ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </KeyDescriptor>
            <AssertionConsumerService Binding="binder" index="1"/>
        </SPSSODescriptor>
    </EntityDescriptor>
</EntityDescriptor>
`;

const shortBadXML = `
<EntityDescriptor> 
    <EntityDescriptor entityID = "tester"></EntityDescriptor>
</EntityDescriptor>
`;

const good = new DOMParser().parseFromString(goodXML, 'text/xml');

const bad = new DOMParser().parseFromString(badXML, 'text/xml');

const shortBad = new DOMParser().parseFromString(shortBadXML, 'text/xml');

const match = { name : 'test' };

console.log = () => {};
console.error = () => {};

describe('SPSSODescriptor checker', function () {

    describe('SPSSODescriptor tester good', function () {
        it('should return true', function () {
            assert.ok(descriptorCheck(good.getElementsByTagName('SPSSODescriptor'), match));
        });
    });

    describe('SPSSODescriptor tester bad', function () {
        it('should return false', function () {
            assert.ok(!descriptorCheck(shortBad.getElementsByTagName('SPSSODescriptor'), match));
        });
    });
});

describe('Getters good', function () {

    describe('Assertion Consumer Service getter', function () {
        it('should return \"Assertion Consumer Service\"', function () {
            assert.strictEqual(getAssertionConsumerService(good.getElementsByTagName('SPSSODescriptor')[0]), 'Assertion Consumer Service');
        });
    });

    describe('InformationURL getter', function () {
        it('should return \"https://information.url\"', function () {
            assert.strictEqual(getInfo(good.getElementsByTagName('SPSSODescriptor')[0]), 'https://information.url');
        });
    });

    describe('Contact getter', function () {
        it('should return [\"other\", \"contact@email.com\"]', function () {
            assert.deepStrictEqual(getContact(good.getElementsByTagName('EntityDescriptor')[0]), [['other', 'contact@email.com']]);
        });
    });

    describe('Requested Attributes getter', function () {
        it('should return [\"required\"]', function () {
            assert.deepStrictEqual(getRequestedAttributes(good.getElementsByTagName('SPSSODescriptor')[0]), ['required']);
        });
    });

    describe('Logo getter', function () {
        it('should return \"data:image/png;base64 ...\"', async function () {
            const testLogo = await getLogo(good.getElementsByTagName('SPSSODescriptor')[0], webproxy);
            assert.ok(testLogo.startsWith('data:image/png;base64'));
        });
    });

    describe('Certificate getter', function () {
        it('should return test certificate', function () {
            const testCert = getCertificate(good.getElementsByTagName('SPSSODescriptor')[0]);
            assert.deepStrictEqual(testCert.fingerprint512, goodCert.fingerprint512);
        });
    });
});

describe('Getters bad', function () {

    describe('Assertion Consumer Service getter', function () {
        it('should return empty string', function () {
            assert.strictEqual(getAssertionConsumerService(bad.getElementsByTagName('SPSSODescriptor')[0]), '');
        });
    });

    describe('InformationURL getter', function () {
        it('should return empty string', function () {
            assert.strictEqual(getInfo(bad.getElementsByTagName('SPSSODescriptor')[0]), '');
        });
    });

    describe('Contact getter', function () {
        it('should return []', function () {
            assert.deepStrictEqual(getContact(bad.getElementsByTagName('EntityDescriptor')[0]), []);
        });
    });

    describe('Requested Attributes getter', function () {
        it('should return []', function () {
            assert.deepStrictEqual(getRequestedAttributes(bad.getElementsByTagName('SPSSODescriptor')[0]), []);
        });
    });

    describe('Logo getter', function () {
        it('should return empty string', async function () {
            const testLogo = await getLogo(bad.getElementsByTagName('SPSSODescriptor')[0], webproxy);
            assert.strictEqual(testLogo, '');
        });
    });

    describe('Certificate getter', function () {
        it('should return null', function () {
            const testCert = getCertificate(bad.getElementsByTagName('SPSSODescriptor')[0]);
            assert.deepStrictEqual(testCert, null);
        });
    });
});

describe('write/delete files', function () {
    describe('good', function () {
        it('should return true', function () {
            writeFiles('test/sp/', {name : 'testfile'}, JSON.stringify({test : 'test'}, null, 2), 'cert', 'pubkey', 'testfile');
            assert.ok(fs.readdirSync('test/sp/').length === 3);

        });
        it('should return true', function () {
            deleteFiles('test/sp/', [], 'testfile');
            assert.ok(fs.readdirSync('test/sp/').length === 0);
        });
    });

    describe('bad delete dir param', function () {
        it('should return true', function () {
            writeFiles('test/sp/', {name : 'testfile'}, JSON.stringify({test : 'test'}, null, 2), 'cert', 'pubkey', 'testfile');
            assert.ok(fs.readdirSync('test/sp/').length === 3);
        });
        it('should throw ENOENT error', function () {
            assert.throws(() => deleteFiles('a/', [], 'testfile'), /ENOENT/);
        });
        it('should return true', function () {
            deleteFiles('test/sp/', [], 'testfile');
            assert.ok(fs.readdirSync('test/sp/').length === 0)
        })
    });
    describe('bad JSON string is null', function () {
        it('should throw ERR_INVALID_ARG_TYPE error', function () {
            assert.throws(() => writeFiles('test/sp/', {name : 'testfile'}, null, 'cert', 'pubkey', 'testfile'), /ERR_INVALID_ARG_TYPE/);
        });
    });
    describe('bad JSON string is empty', function () {
        it('should throw ERR_INVALID_ARG_TYPE error', function () {

            let captured = '';
            console.error = (msg) => { captured += msg; };

            writeFiles('test/sp/', {name : 'testfile'}, '', 'cert', 'pubkey', 'testfile')

            assert.strictEqual(captured, 'JSON String is empty.');
        });
    });
});