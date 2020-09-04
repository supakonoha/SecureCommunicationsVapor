//  Data+ChaChaPoly.swift
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

import Foundation
import Crypto

extension Data {
    /**
     Encrypts current data using ChaChaPoly cipher.

     - Parameters:
         - senderPrivateKey: Sender private key.
         - recipientPublicKey: Recipient public key.
         - salt: The salt to use for key derivation.

     - Returns: combined ChaChaPoly Selead box  (nonce || ciphertext || tag). If there's a problem encrypting, nil is retuned.
     */
    func sealChaChaPoly(senderPrivateKey: P256.KeyAgreement.PrivateKey, recipientPublicKey: P256.KeyAgreement.PublicKey, salt: Data) -> Data? {
        guard let keyStore = try? KeyStore(privateKey: senderPrivateKey) else {
            return nil
        }

        guard let symmetricKey = try? keyStore.getSymmetricKey(
                publicKey: recipientPublicKey,
                salt: salt) else {
            return nil
        }

        return try? ChaChaPoly.seal(self, using: symmetricKey).combined
    }

    /**
     Decrypts current combined ChaChaPoly Selead box data (nonce || ciphertext || tag) using ChaChaPoly cipher.

     - Parameters:
         - recipientPrivateKey: Recipient private key.
         - senderPublicKey: Sender public key.
         - salt: The salt to use for key derivation.

     - Returns: Decrypts the message and verifies its authenticity using ChaChaPoly. If there's a problem decrypting, nil is retuned.
     */
    func openChaChaPoly(recipientPrivateKey: P256.KeyAgreement.PrivateKey, senderPublicKey: P256.KeyAgreement.PublicKey, salt: Data) -> Data? {
        guard let keyStore = try? KeyStore(privateKey: recipientPrivateKey) else {
            return nil
        }

        guard let symmetricKey = try? keyStore.getSymmetricKey(
                publicKey: senderPublicKey,
                salt: salt) else {
            return nil
        }

        guard let ChaChaPolySealedBox = try? ChaChaPoly.SealedBox(combined: self) else {
            return nil
        }

        return try? ChaChaPoly.open(ChaChaPolySealedBox, using: symmetricKey)
    }
}
