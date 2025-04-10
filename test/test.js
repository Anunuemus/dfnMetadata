var assert = require('assert');
const { DOMParser } = require('xmldom');

const { getAssertionConsumerService, getInfo, getContact, getRequestedAttributes, getLogo } = require('../getMetadata')



const assertionConsumerService = `
<EntityDescriptor entityID = "tester">
    <SPSSODescriptor>
        <Extensions>
            <mdui:InformationURL>https://information.url</mdui:InformationURL>
            <mdui:Logo>https://placehold.co/10/png<mdui:/Logo>
        </Extensions>
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
`
const doc = new DOMParser().parseFromString(assertionConsumerService, 'text/xml');

describe('Getters', function () {
    describe('Assertion Consumer Service getter', function () {
        it('should return \"Assertion Consumer Service\"', function () {
            assert.strictEqual(getAssertionConsumerService(doc.getElementsByTagName('SPSSODescriptor')[0]), 'Assertion Consumer Service')
        });
    });

    describe('InformationURL getter', function () {
        it('should return \"https://information.url\"', function () {
            assert.strictEqual(getInfo(doc.getElementsByTagName('SPSSODescriptor')[0]), 'https://information.url')
        });
    });

    describe('Contact getter', function () {
        it('should return [\"other\", \"contact@email.com\"]', function () {
            assert.deepStrictEqual(getContact(doc.getElementsByTagName('EntityDescriptor')[0]), [['other', 'contact@email.com']])
        });
    });

    describe('Requested Attributes getter', function () {
        it('should return [\"required\"]', function () {
            assert.deepStrictEqual(getRequestedAttributes(doc.getElementsByTagName('SPSSODescriptor')[0]), ['required'])
        });
    });

    describe('Logo getter', function () {
        it('should return [\"required\"]', async function () {
            this.timeout(5000);
            const testLogo = await getLogo(doc.getElementsByTagName('SPSSODescriptor')[0], "");
            console.log(testLogo);
            assert.ok(testLogo.startsWith('data:image/png;base64'));
        });
    });
});