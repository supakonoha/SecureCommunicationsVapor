//
//  String+AESTests.swift
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
final class StringAESTests: XCTestCase {
    private let message = "This is top secret"
    private let salt = "Here's some salt data to use for testing"
    private let senderPrivateKey = P256.KeyAgreement.PrivateKey()
    private let recipientPrivateKey = P256.KeyAgreement.PrivateKey()

    override func setUp() {
    }

    override func tearDown() {
    }

    func test_Given_Data_When_EncryptWithPrivateKey_Then_EncryptedValue() {
        let encryptedMessage = message.sealAES(
            senderPrivateKey: senderPrivateKey,
            recipientPublicKey: recipientPrivateKey.publicKey,
            salt: salt)

        XCTAssertNotNil(encryptedMessage)
        XCTAssertNotEqual(message, encryptedMessage)
    }

    func test_Given_Data_When_EncryptWithPrivateKeyAndDecrypt_Then_OriginalValue() throws {
        guard let encryptedMessage = message.sealAES(
                senderPrivateKey: senderPrivateKey,
                recipientPublicKey: recipientPrivateKey.publicKey,
                salt: salt) else {
            XCTFail("Encrypted message cannot be nil")
            return
        }

        guard let decryptedMessage = encryptedMessage.openAES(
                recipientPrivateKey: recipientPrivateKey,
                senderPublicKey: senderPrivateKey.publicKey,
                salt: salt) else {
            XCTFail("Decrypted message cannot be nil")
            return
        }

        XCTAssertEqual(message, decryptedMessage)
    }

    func test_Given_WrongSizeMessage_When_DecryptWithPrivateKeyOnRecipient_Then_Nil() throws {
        let decryptedMessage = "".openAES(
            recipientPrivateKey: recipientPrivateKey,
            senderPublicKey: senderPrivateKey.publicKey,
            salt: salt)

        XCTAssertNil(decryptedMessage)
    }

    func test_Given_Data_When_EncryptBySenderAndDecryptWithPrivateKeyAndWithWrongPublicKeyOnRecipient_Then_Nil() throws {
        guard let encryptedMessage = message.sealAES(
                senderPrivateKey: senderPrivateKey,
                recipientPublicKey: recipientPrivateKey.publicKey,
                salt: salt) else {
            XCTFail("Encrypted message cannot be nil")
            return
        }

        let newPrivateKey = P256.KeyAgreement.PrivateKey()

        let decryptedMessage = encryptedMessage.openAES(
            recipientPrivateKey: recipientPrivateKey,
            senderPublicKey: newPrivateKey.publicKey,
            salt: salt)

        XCTAssertNil(decryptedMessage)
    }
}
