//
//  KeyStore.swift
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

/// Tools to create Crypto keys
public struct KeyStore {
    /// P-256 private key
    private var privateKey: P256.KeyAgreement.PrivateKey

    /**
     Returns a P256.KeyAgreement.PrivateKey instance of an ANSI x9.63 representation of the private key.

     - Parameter x963Representation: ANSI x9.63 representation of the private key.

     - Throws: An error during the private key process

     - Returns: P256.KeyAgreement.PrivateKey instance of the private key.
     */
    static func privateKey(x963Representation: Data) throws -> P256.KeyAgreement.PrivateKey {
        return try P256.KeyAgreement.PrivateKey(x963Representation: x963Representation)
    }

    /**
     Returns a P256.KeyAgreement.PrivateKey instance of raw representation of the private key.

     - Parameter rawRepresentation: raw representation of the private key.

     - Throws: An error during the private key process

     - Returns: P256.KeyAgreement.PrivateKey instance of the private key.
     */
    static func privateKey(rawRepresentation: Data) throws -> P256.KeyAgreement.PrivateKey {
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
    }

    /**
     Returns a P256.KeyAgreement.PrivateKey instance of pem representation of the private key.

     - Parameter pemRepresentation: pem representation of the private key.

     - Throws: An error during the private key process

     - Returns: P256.KeyAgreement.PrivateKey instance of the private key.
     */
    static func privateKey(pemRepresentation: String) throws -> P256.KeyAgreement.PrivateKey {
        return try P256.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation)
    }

    /**
     Returns a P256.KeyAgreement.PrivateKey instance of der representation of the private key.

     - Parameter derRepresentation: der representation of the private key.

     - Throws: An error during the private key process

     - Returns: P256.KeyAgreement.PrivateKey instance of the private key.
     */
    static func privateKey(derRepresentation: Data) throws -> P256.KeyAgreement.PrivateKey {
        return try P256.KeyAgreement.PrivateKey(derRepresentation: derRepresentation)
    }

    /**
     Returns a P256.KeyAgreement.PublicKey instance of an ANSI x9.63 representation of the public key.

     - Parameter x963Representation: ANSI x9.63 representation of the public key.

     - Throws: An error during the public key process

     - Returns: P256.KeyAgreement.PublicKey instance of the public key.
     */
    static func publicKey(x963Representation: Data) throws -> P256.KeyAgreement.PublicKey {
        return try P256.KeyAgreement.PublicKey(x963Representation: x963Representation)
    }

    /**
     Returns a P256.KeyAgreement.PublicKey instance of raw representation of the public key.

     - Parameter rawRepresentation: raw representation of the public key.

     - Throws: An error during the public key process

     - Returns: P256.KeyAgreement.PublicKey instance of the public key.
     */
    static func publicKey(rawRepresentation: Data) throws -> P256.KeyAgreement.PublicKey {
        return try P256.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
    }

    /**
     Returns a P256.KeyAgreement.PublicKey instance of the public key of a pem representation

     - Parameter pemRepresentation: pem representation of the public key.

     - Throws: An error during the public key process

     - Returns: P256.KeyAgreement.PublicKey instance of the public key.
     */
    static func publicKey(pemRepresentation: String) throws -> P256.KeyAgreement.PublicKey {
        return try P256.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation)
    }

    /**
     Returns a P256.KeyAgreement.PublicKey instance of der representation of the public key.

     - Parameter derRepresentation: der representation of the public key.

     - Throws: An error during the public key process

     - Returns: P256.KeyAgreement.PublicKey instance of the public key.
     */
    static func publicKey(derRepresentation: Data) throws -> P256.KeyAgreement.PublicKey {
        return try P256.KeyAgreement.PublicKey(derRepresentation: derRepresentation)
    }

    /**
     Initilializes KeyStore instance

     - Parameter privateKey: P256.KeyAgreement.PrivateKey instance of the private key.

     - Throws: An error during the private key initialization
     */
    internal init(privateKey: P256.KeyAgreement.PrivateKey) throws {
        self.privateKey = privateKey
    }

    /**
     Returns a symmetric key using private key

     - Parameters:
        - publicKey: P256.KeyAgreement.PublicKey
        - salt: The salt to use for key derivation.

     - Throws: An error during shared secret creation

     - Returns: Symmetric key.
     */
    internal func getSymmetricKey(
        publicKey: P256.KeyAgreement.PublicKey,
        salt:Data) throws -> SymmetricKey {

        return try privateKey
            .sharedSecretFromKeyAgreement(with: publicKey)
            .hkdfDerivedSymmetricKey(
                using: SHA512.self,
                salt: salt,
                sharedInfo: Data(),
                outputByteCount: 32)
    }
}
