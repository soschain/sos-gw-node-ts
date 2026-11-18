// Flow contract: the gateway uses independent multibase and JSON encoding contracts; byte roundtrips preserve the original message without granting identity or access.

import { Content } from 'antifraud-data-utils-ts/cryptography';
import { encodeBase58btc, decodeBase58btc } from 'antifraud-data-utils-ts/encoding';

describe("Content Class - Conversion Utilities", () => {

    describe("Base58 Conversions", () => {
        it("should encode and decode a string to/from Base58", () => {
            const testString = "Hello world!";
            const testBytes = Content.stringToBytesUTF8(testString);

            // Encode
            const encoded = encodeBase58btc(testBytes);
            expect(encoded).toBe("z2NEpo7TZRhna7vSvL");

            // Decode
            const decodedBytes = decodeBase58btc(encoded);
            const decodedString = Content.bytesToStringUTF8(decodedBytes);

            expect(decodedString).toBe(testString);
        });
    });

    describe("Base64URL Conversions", () => {
        it("should encode and decode bytes to/from raw Base64URL", () => {
            const testString = "some important data!?";
            const testBytes = Content.stringToBytesUTF8(testString);

            // Encode
            const encoded = Content.bytesToRawBase64UrlSafe(testBytes);
            expect(encoded).toBe("c29tZSBpbXBvcnRhbnQgZGF0YSE_");

            // Decode
            const decodedBytes = Content.base64ToBytes(encoded);
            expect(decodedBytes).toEqual(testBytes);
        });
    });

    describe("Object Serialization", () => {
        it("should serialize and deserialize an object to/from raw Base64URL", () => {
            const testObject = {
                id: "12345",
                aud: ["did:web:example.com"],
                exp: 1678886400,
                verified: true,
            };

            // Serialize
            const encoded = Content.objectToRawBase64UrlSafe(testObject);

            // Deserialize
            const decodedObject = Content.base64UrlSafeToJSON(encoded);

            expect(decodedObject).toEqual(testObject);
        });
    });

});

