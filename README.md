# DFNMetadata
A script that fetches DFN SP Metadata XML and retrieves metadata of the SPs as provided in config.json. 

Creates a JSON-file (s. template.json), .crt and .pub for each SP respectively.

## Installation
Script requires 'https-proxy-agent', 'xmldom', 'xml-crypto' and 'node-forge'
```bash
npm install https-proxy-agent xmldom xml-crypto node-forge
```
## Usage
Configure config.json (and l.217 url if needed) and run getMetadata.js.
```bash
node ./getMetadata.js
```

## Notes
The `name` attribute in config should not contain `-`, otherwise the `deleteFiles()` function will not work properly.

The `getCertificate()` function will probably not work properly on SPs with several certificates with different KeyNames or seperate certificates for encryption and signing.
