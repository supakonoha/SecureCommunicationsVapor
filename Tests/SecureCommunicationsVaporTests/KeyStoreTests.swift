//
//  KeyStoreTests.swift
//
//  Created by Supakonoha on 31/01/2020.
//
//  Copyright (c) 2020 Supakonoha
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import XCTest
import Crypto
@testable import SecureCommunicationsVapor

/// To run these tests on MacOS you need XCode 12
final class KeyStoreTests: XCTestCase {
    private let salt = "Here's some salt data to use for testing".data(using: .utf8)!

    private let privateKeyX963 = Data(base64Encoded: "BEBZeDGX55fQ/DOqk4bcX8IoZ96zBOfHOWtAxJdhrMIGIBRfSiLDoDJYNYSthnli+37gEDZqbYFO9qlkBSSS9WtxQxd8gXPP4kIrXKFGMdrUql9DIKnaaqHtE+6eBOCYKg==")!
    private let privateKeyRaw = Data(base64Encoded: "cUMXfIFzz+JCK1yhRjHa1KpfQyCp2mqh7RPungTgmCo=")!
    private let privateKeyDer = Data(base64Encoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcUMXfIFzz+JCK1yhRjHa1KpfQyCp2mqh7RPungTgmCqhRANCAARAWXgxl+eX0PwzqpOG3F/CKGfeswTnxzlrQMSXYazCBiAUX0oiw6AyWDWErYZ5Yvt+4BA2am2BTvapZAUkkvVr")!
    private let privateKeyPem = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcUMXfIFzz+JCK1yh
RjHa1KpfQyCp2mqh7RPungTgmCqhRANCAARAWXgxl+eX0PwzqpOG3F/CKGfeswTn
xzlrQMSXYazCBiAUX0oiw6AyWDWErYZ5Yvt+4BA2am2BTvapZAUkkvVr
-----END PRIVATE KEY-----
"""
    private var privateKey: P256.KeyAgreement.PrivateKey!

    private let publicKeyX963 = Data(base64Encoded: "BEBZeDGX55fQ/DOqk4bcX8IoZ96zBOfHOWtAxJdhrMIGIBRfSiLDoDJYNYSthnli+37gEDZqbYFO9qlkBSSS9Ws=")!
    private let publicKeyRaw = Data(base64Encoded: "QFl4MZfnl9D8M6qThtxfwihn3rME58c5a0DEl2GswgYgFF9KIsOgMlg1hK2GeWL7fuAQNmptgU72qWQFJJL1aw==")!
    private let publicKeyDer = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFl4MZfnl9D8M6qThtxfwihn3rME58c5a0DEl2GswgYgFF9KIsOgMlg1hK2GeWL7fuAQNmptgU72qWQFJJL1aw==")!
    private let publicKeyPem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFl4MZfnl9D8M6qThtxfwihn3rME
58c5a0DEl2GswgYgFF9KIsOgMlg1hK2GeWL7fuAQNmptgU72qWQFJJL1aw==
-----END PUBLIC KEY-----
"""

    private let recipientPrivateKeyX963 = Data(base64Encoded: "BGjoJI0K4Yp8DWZtYpmYTgoVfn10aeOmXGeehjr1PYjvF4sjI9FkJ3NT68KLYryksyanzDvgd7291dbToHam3CJ3/ScEqJ9EM1+RLqW6H5a9h+DxR36xoaVYQbMS+BIsqA==")!
    private let recipientPrivateKeyRaw = Data(base64Encoded: "d/0nBKifRDNfkS6luh+WvYfg8Ud+saGlWEGzEvgSLKg=")!
    private let recipientPrivateKeyDer = Data(base64Encoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgd/0nBKifRDNfkS6luh+WvYfg8Ud+saGlWEGzEvgSLKihRANCAARo6CSNCuGKfA1mbWKZmE4KFX59dGnjplxnnoY69T2I7xeLIyPRZCdzU+vCi2K8pLMmp8w74He9vdXW06B2ptwi")!
    private let recipientPrivateKeyPem = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgd/0nBKifRDNfkS6l
uh+WvYfg8Ud+saGlWEGzEvgSLKihRANCAARo6CSNCuGKfA1mbWKZmE4KFX59dGnj
plxnnoY69T2I7xeLIyPRZCdzU+vCi2K8pLMmp8w74He9vdXW06B2ptwi
-----END PRIVATE KEY-----
"""
    private var recipientPrivateKey: P256.KeyAgreement.PrivateKey!

    private let recipientPublicKeyX963 = Data(base64Encoded: "BGjoJI0K4Yp8DWZtYpmYTgoVfn10aeOmXGeehjr1PYjvF4sjI9FkJ3NT68KLYryksyanzDvgd7291dbToHam3CI=")!
    private let recipientPublicKeyRaw = Data(base64Encoded: "aOgkjQrhinwNZm1imZhOChV+fXRp46ZcZ56GOvU9iO8XiyMj0WQnc1PrwotivKSzJqfMO+B3vb3V1tOgdqbcIg==")!
    private let recipientPublicKeyDer = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaOgkjQrhinwNZm1imZhOChV+fXRp46ZcZ56GOvU9iO8XiyMj0WQnc1PrwotivKSzJqfMO+B3vb3V1tOgdqbcIg==")!
    private let recipientPublicKeyPem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaOgkjQrhinwNZm1imZhOChV+fXRp
46ZcZ56GOvU9iO8XiyMj0WQnc1PrwotivKSzJqfMO+B3vb3V1tOgdqbcIg==
-----END PUBLIC KEY-----
"""

    override func setUp() {
        privateKey = try! P256.KeyAgreement.PrivateKey(pemRepresentation: privateKeyPem)
        recipientPrivateKey = try! P256.KeyAgreement.PrivateKey(pemRepresentation: recipientPrivateKeyPem)
    }

    override func tearDown() {
    }

    func test_Given_WrongPrivateKeyinX963Representation_When_GetPrivateKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.privateKey(x963Representation: Data()))
        XCTAssertThrowsError(try KeyStore.privateKey(x963Representation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_WrongPrivateKeyinRawRepresentation_When_GetPrivateKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.privateKey(rawRepresentation: Data()))
        XCTAssertThrowsError(try KeyStore.privateKey(rawRepresentation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_WrongPrivateKeyinPemRepresentation_When_GetPrivateKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.privateKey(pemRepresentation: ""))
        XCTAssertThrowsError(try KeyStore.privateKey(pemRepresentation: "WrongData"))
    }

    func test_Given_WrongPrivateKeyinDerRepresentation_When_GetPrivateKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.privateKey(derRepresentation: Data()))
        XCTAssertThrowsError(try KeyStore.privateKey(derRepresentation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_WrongPublicKeyinX963Representation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(x963Representation: Data()))
        XCTAssertThrowsError(try KeyStore.publicKey(x963Representation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_WrongPublicKeyinRawRepresentation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(rawRepresentation: Data()))
        XCTAssertThrowsError(try KeyStore.publicKey(rawRepresentation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_WrongPublicKeyinPemRepresentation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(pemRepresentation: ""))
        XCTAssertThrowsError(try KeyStore.publicKey(pemRepresentation: "WrongData"))
    }

    func test_Given_WrongPublicKeyinDerRepresentation_When_GetPublicKey_Then_Exception() throws {
        XCTAssertThrowsError(try KeyStore.publicKey(derRepresentation: Data()))
        XCTAssertThrowsError(try KeyStore.publicKey(derRepresentation: "WrongData".data(using: .utf8)!))
    }

    func test_Given_PrivateKeyinX963Representation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let privateKey = try KeyStore.privateKey(x963Representation: privateKeyX963)

        XCTAssertEqual(privateKey.x963Representation, privateKeyX963)
        XCTAssertEqual(privateKey.rawRepresentation, privateKeyRaw)
        XCTAssertEqual(privateKey.pemRepresentation, privateKeyPem)
        XCTAssertEqual(privateKey.derRepresentation, privateKeyDer)
    }

    func test_Given_NewPrivateKeyinX963Representation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let newPrivateKey = P256.KeyAgreement.PrivateKey()
        let privateKey = try KeyStore.privateKey(x963Representation: newPrivateKey.x963Representation)

        XCTAssertEqual(privateKey.x963Representation, newPrivateKey.x963Representation)
        XCTAssertEqual(privateKey.rawRepresentation, newPrivateKey.rawRepresentation)
        XCTAssertEqual(privateKey.pemRepresentation, newPrivateKey.pemRepresentation)
        XCTAssertEqual(privateKey.derRepresentation, newPrivateKey.derRepresentation)
    }

    func test_Given_PrivateKeyinRawRepresentation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let privateKey = try KeyStore.privateKey(rawRepresentation: privateKeyRaw)

        XCTAssertEqual(privateKey.x963Representation, privateKeyX963)
        XCTAssertEqual(privateKey.rawRepresentation, privateKeyRaw)
        XCTAssertEqual(privateKey.pemRepresentation, privateKeyPem)
        XCTAssertEqual(privateKey.derRepresentation, privateKeyDer)
    }

    func test_Given_NewPrivateKeyinRawRepresentation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let newPrivateKey = P256.KeyAgreement.PrivateKey()
        let privateKey = try KeyStore.privateKey(rawRepresentation: newPrivateKey.rawRepresentation)

        XCTAssertEqual(privateKey.x963Representation, newPrivateKey.x963Representation)
        XCTAssertEqual(privateKey.rawRepresentation, newPrivateKey.rawRepresentation)
        XCTAssertEqual(privateKey.pemRepresentation, newPrivateKey.pemRepresentation)
        XCTAssertEqual(privateKey.derRepresentation, newPrivateKey.derRepresentation)
    }

    func test_Given_PrivateKeyinPemRepresentation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let privateKey = try KeyStore.privateKey(pemRepresentation: privateKeyPem)

        XCTAssertEqual(privateKey.x963Representation, privateKeyX963)
        XCTAssertEqual(privateKey.rawRepresentation, privateKeyRaw)
        XCTAssertEqual(privateKey.pemRepresentation, privateKeyPem)
        XCTAssertEqual(privateKey.derRepresentation, privateKeyDer)
    }

    func test_Given_NewPrivateKeyinPemRepresentation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let newPrivateKey = P256.KeyAgreement.PrivateKey()
        let privateKey = try KeyStore.privateKey(pemRepresentation: newPrivateKey.pemRepresentation)

        XCTAssertEqual(privateKey.x963Representation, newPrivateKey.x963Representation)
        XCTAssertEqual(privateKey.rawRepresentation, newPrivateKey.rawRepresentation)
        XCTAssertEqual(privateKey.pemRepresentation, newPrivateKey.pemRepresentation)
        XCTAssertEqual(privateKey.derRepresentation, newPrivateKey.derRepresentation)
    }

    func test_Given_PrivateKeyinDerRepresentation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let privateKey = try KeyStore.privateKey(derRepresentation: privateKeyDer)

        XCTAssertEqual(privateKey.x963Representation, privateKeyX963)
        XCTAssertEqual(privateKey.rawRepresentation, privateKeyRaw)
        XCTAssertEqual(privateKey.pemRepresentation, privateKeyPem)
        XCTAssertEqual(privateKey.derRepresentation, privateKeyDer)
    }

    func test_Given_NewPrivateKeyinDerRepresentation_When_GetPrivateKey_Then_PrivateKeyIsEqualToOriginal() throws {
        let newPrivateKey = P256.KeyAgreement.PrivateKey()
        let privateKey = try KeyStore.privateKey(derRepresentation: newPrivateKey.derRepresentation)

        XCTAssertEqual(privateKey.x963Representation, newPrivateKey.x963Representation)
        XCTAssertEqual(privateKey.rawRepresentation, newPrivateKey.rawRepresentation)
        XCTAssertEqual(privateKey.pemRepresentation, newPrivateKey.pemRepresentation)
        XCTAssertEqual(privateKey.derRepresentation, newPrivateKey.derRepresentation)
    }

    func test_Given_PublicKeyinX963Representation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(x963Representation: publicKeyX963)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
        XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
    }

    func test_Given_NewPublicKeyinX963Representation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(x963Representation: newPublicKey.x963Representation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
        XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
    }

    func test_Given_PublicKeyinRawRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(rawRepresentation: publicKeyRaw)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
        XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
    }

    func test_Given_NewPublicKeyinRawRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(rawRepresentation: newPublicKey.rawRepresentation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
        XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
    }

    func test_Given_PublicKeyinPemRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(pemRepresentation: publicKeyPem)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
        XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
    }

    func test_Given_NewPublicKeyinPemRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(pemRepresentation: newPublicKey.pemRepresentation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
        XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
    }

    func test_Given_PublicKeyinDerRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let publicKey = try KeyStore.publicKey(derRepresentation: publicKeyDer)

        XCTAssertEqual(publicKey.x963Representation, publicKeyX963)
        XCTAssertEqual(publicKey.rawRepresentation, publicKeyRaw)
        XCTAssertEqual(publicKey.pemRepresentation, publicKeyPem)
        XCTAssertEqual(publicKey.derRepresentation, publicKeyDer)
    }

    func test_Given_NewPublicKeyinDerRepresentation_When_GetPublicKey_Then_PublicKeyIsEqualToOriginal() throws {
        let newPublicKey = P256.KeyAgreement.PrivateKey().publicKey
        let publicKey = try KeyStore.publicKey(derRepresentation: newPublicKey.derRepresentation)

        XCTAssertEqual(publicKey.x963Representation, newPublicKey.x963Representation)
        XCTAssertEqual(publicKey.rawRepresentation, newPublicKey.rawRepresentation)
        XCTAssertEqual(publicKey.pemRepresentation, newPublicKey.pemRepresentation)
        XCTAssertEqual(publicKey.derRepresentation, newPublicKey.derRepresentation)
    }

    func test_Given_PrivateKey_When_GenerateSymmetricKey_Then_SymmetricKeyNotNull() throws {
        let keyStore = try KeyStore(privateKey: privateKey)

        XCTAssertNotNil(try keyStore.getSymmetricKey(publicKey: KeyStore.publicKey(pemRepresentation: recipientPublicKeyPem), salt: salt))
    }

    func test_Given_TwoPrivateKeys_When_GenerateSymmetricKeys_Then_SymmetricKeysAreEqual() throws {
        let keyStore = try KeyStore(privateKey: privateKey)
        let recipientKeyStore = try KeyStore(privateKey: recipientPrivateKey)

        let symmetricKey = try keyStore.getSymmetricKey(
            publicKey: KeyStore.publicKey(pemRepresentation: recipientPublicKeyPem),
            salt: salt)

        let recipientSymmetricKey = try recipientKeyStore.getSymmetricKey(
            publicKey: KeyStore.publicKey(pemRepresentation: publicKeyPem),
            salt: salt)

        XCTAssertEqual(symmetricKey, recipientSymmetricKey)
    }

    func test_Given_TwoNewPrivateKeys_When_GenerateSymmetricKeys_Then_SymmetricKeysAreEqual() throws {
        let privateKey1 = P256.KeyAgreement.PrivateKey()
        let privateKey2 = P256.KeyAgreement.PrivateKey()

        let keyStore = try KeyStore(privateKey: privateKey1)
        let recipientKeyStore = try KeyStore(privateKey: privateKey2)

        let symmetricKey = try keyStore.getSymmetricKey(
            publicKey: KeyStore.publicKey(pemRepresentation: privateKey2.publicKey.pemRepresentation),
            salt: salt)

        let recipientSymmetricKey = try recipientKeyStore.getSymmetricKey(
            publicKey: KeyStore.publicKey(pemRepresentation: privateKey1.publicKey.pemRepresentation),
            salt: salt)

        XCTAssertEqual(symmetricKey, recipientSymmetricKey)
    }

}
