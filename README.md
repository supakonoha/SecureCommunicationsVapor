# SecureCommunicationsVapor

![badge-languages][] ![badge-pms][] ![badge-swift][] ![badge-platforms][]

---

SecureCommunicationsVapor simplifies Swift Crypto tasks using AES and ChaChaPoly Ciphers and HMAC Message Authentication Codes on the backend side (using [Vapor](https://vapor.codes)).

```swift
let salt = "This is our salt"
let message = "This is a top secret message"

let encryptedMessage = message.sealAES(
    privateKeyPemRepresentation: senderPrivateKey,
    recipientPublicKey: recipientPublicKey,
    salt: salt)
```

# Note

This library requires [Swift Crypto 1.1.0 RC 2](https://github.com/apple/swift-crypto) 

Minimum requirements: Swift 5.3

If you are working on MacOS you will need MacOS Big Sur and Xcode 12

This library is related with [`SecureCommunications`](https://github.com/supakonoha/SecureCommunications).

This library can be used on [Vapor](https://vapor.codes) on the server side.

# Quick Start

#### Add dependencies

Add the `SecureCommunicationsVapor` paclage to the dependencies within your appliction's `Package.swift` file:

```swift
.package(url: "https://github.com/supakonoha/SecureCommunicationsVapor", from: "1.0.0")
```

Add  `SecureCommunicationsVapor` to your target's dependencies:

```swift
.target(name: "example", dependencies: ["SecureCommunicationsVapor"]),
```

#### Import package

```swift
import SecureCommunicationsVapor
```

# Private Key and Public Key

You can use OpenSSL and the command line elliptic curve operations to create a P-256 private and public keys. 

```
$ openssl ecparam -name prime256v1 -genkey -noout -out key.pem
```

These keys will be formatted as follows:

```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEYPPsCq/SoJ1a9i8Bv4MlD6XWF3qQRV0UPxiRihq7TboAoGCCqGSM49
AwEHoUQDQgAEk11YXwj6kQ88xQbC7T9oU5K/dcVal/W8g+6gxjz8w7VDl9BZpqgt
F8jJuC2vM5YmKK3nXD8DB+OVuCfPB1/lqg==
-----END EC PRIVATE KEY-----
```

You will need your server private key to initialize a `Keystore`. It creates internally a shared secret between two users by performing NIST P-256 elliptic curve Diffie Hellman (ECDH) key exchange.

If you want to send an encrypted message you will need to share your Public Key. For that you can use:

```
$ openssl ec -in key.pem -pubout -out public.pem
```

These keys will be formatted as follows:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk11YXwj6kQ88xQbC7T9oU5K/dcVa
l/W8g+6gxjz8w7VDl9BZpqgtF8jJuC2vM5YmKK3nXD8DB+OVuCfPB1/lqg==
-----END PUBLIC KEY-----
```

You need to share your public key with the other part. If you want to use HMAC to validate the calls to your API, or encrypt your messages and be sure that are coming from your App only, please, share the public key in a secure way like using `CloudKit`. Please, don't hard-code the public key on the source code or abfuscate it, don't store it on Xcode Configuration or Info.plist files and never stores it on device once you have received it. If you have it on CloudKit or a similar service you can renew your private and public keys with no changes on your app.

# KeyStore

This class gives some tools to manage keys on ANSI x9.63, RAW, PEM and DER representation.

## Get a private key

If you have a private key on an ANSI x9.63, RAW, PEM or DER representation you can obtain a `P256.KeyAgreement.PrivateKey` instance. You will need it for encryption and authentication code operations.

### From an ANSI x9.63 representation

You can use the static `privateKey` function on `Keystore` struct.

```swift
let privateKey = try KeyStore.privateKey(x963Representation: x963RepresentationPrivateKey)
```

### From a RAW representation

You can use the static `privateKey` function on `Keystore` struct.

```swift
let privateKey = try KeyStore.privateKey(rawRepresentation: rawRepresentationPrivateKey)
```

### From a PEM representation

You can use the static `privateKey` function on `Keystore` struct.

```swift
let privateKey = try KeyStore.privateKey(pemRepresentation: pemRepresentationPrivateKey)
```

### From an DER representation

You can use the static `privateKey` function on `Keystore` struct.

```swift
let privateKey = try KeyStore.privateKey(derRepresentation: derRepresentationPrivateKey)
```

## Get a public key

If you have a public key on an ANSI x9.63, RAW, PEM or DER representation you can obtain a `P256.KeyAgreement.PublicKey` instance. You will need it for encryption and authentication code operations.

### From an ANSI x9.63 representation

You can use the static `publicKey` function on `Keystore` struct.

```swift
let publicKey = try KeyStore.publicKey(x963Representation: x963RepresentationPublicKey)
```

### From a RAW representation

You can use the static `publicKey` function on `Keystore` struct.

```swift
let publicKey = try KeyStore.publicKey(rawRepresentation: rawRepresentationPublicKey)
```

### From a PEM representation

You can use the static `publicKey` function on `Keystore` struct.

```swift
let publicKey = try KeyStore.publicKey(pemRepresentation: pemRepresentationPublicKey)
```

### From an DER representation

You can use the static `publicKey` function on `Keystore` struct.

```swift
let publicKey = try KeyStore.publicKey(derRepresentation: derRepresentationPublicKey)
```

# Ciphers

If you want to encrypt a message and send it to a recipient you can use AES and ChaChaPoly. The recipient of the encrypted message will use same cipher and will need your public key and the salt used for creating the symmetic key. For the full process you will need:

- The message: Original message if you want to encrypt, or encrypted message if you want to decrypt it
- Your private key: A `P256.KeyAgreement.PrivateKey` instance of the private key.
- Public key of the other part: A `P256.KeyAgreement.PublicKey` instance of the public key of other part.
- Your public key: You will need to pass to the other part, so it can encrypt or decrypt.
- Salt: The salt to use for key derivation. This salt can be shared between sender and recipient.

## AES.GCM

The Advanced Encryption Standard (AES) Galois Counter Mode (GCM) cipher suite.

### Encrypt a message

To encrypt a message the library has added some extensions to `String` and `Data` classes.

If you want to encrypt some `Data` you will need to use `sealAES(senderPrivateKey: P256.KeyAgreement.PrivateKey, recipientPublicKey: P256.KeyAgreement.PublicKey, salt: Data)` function on the original message. It requieres you private key, the other part public key and the salt. You will receive the encrypted message that you can send to the other part with your public key and the salt.

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a top secret message".data(using: .utf8)!

let encryptedMessage = message.sealAES(
    senderPrivateKey: senderPrivateKey,
    recipientPublicKey: recipientPrivateKey.publicKey,
    salt: salt)
```

If you want to encrypt some `String` you will need to use `sealAES(senderPrivateKey: P256.KeyAgreement.PrivateKey, recipientPublicKey: P256.KeyAgreement.PublicKey, salt: String)` function on the original message. It requieres you private key, the other part public key and the salt. You will receive the encrypted message that you can send to the other part with your public key and the salt.

```swift
let salt = "This is our salt"
let message = "This is a top secret message"

let encryptedMessage = message.sealAES(
    senderPrivateKey: senderPrivateKey,
    recipientPublicKey: recipientPrivateKey.publicKey,
    salt: salt)
```

### Decrypt a message

To decrypt a message the library has added some extensions to `String` and `Data` classes.

If you want to decrypt some `Data` you will need to use `openAES(recipientPrivateKey: P256.KeyAgreement.PrivateKey, senderPublicKey: P256.KeyAgreement.PublicKey, salt: Data)` function on the encrypted message. It requieres you private key, the other part public key and the salt. You will receive the original message.

```swift
let salt = "This is our salt".data(using: .utf8)!

let message = encryptedMessage.openAES(
    recipientPrivateKey: recipientPrivateKey,
    senderPublicKey: senderPublicKey,
    salt: salt)
```

If you want to decrypt some `String` you will need to use `openAES(recipientPrivateKey: P256.KeyAgreement.PrivateKey, senderPublicKey: P256.KeyAgreement.PublicKey, salt: String)` function on the encrypted message. It requieres you private key, the other part public key and the salt. You will receive the original message.

```swift
let salt = "This is our salt"

let message = encryptedMessage.openAES(
    recipientPrivateKey: recipientPrivateKey,
    senderPublicKey: senderPublicKey,
    salt: salt)
```

## ChaChaPoly

ChaCha20-Poly1305 cipher.

### Encrypt a message

To encrypt a message the library has added some extensions to `String` and `Data` classes.

If you want to encrypt some `Data` you will need to use `sealChaChaPoly(senderPrivateKey: P256.KeyAgreement.PrivateKey, recipientPublicKey: P256.KeyAgreement.PublicKey, salt: Data)` function on the original message. It requieres you private key, the other part public key and the salt. You will receive the encrypted message that you can send to the other part with your public key and the salt.

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a top secret message".data(using: .utf8)!

let encryptedMessage = message.sealChaChaPoly(
    senderPrivateKey: senderPrivateKey,
    recipientPublicKey: recipientPrivateKey.publicKey,
    salt: salt)
```

If you want to encrypt some `String` you will need to use `sealChaChaPoly(senderPrivateKey: P256.KeyAgreement.PrivateKey, recipientPublicKey: P256.KeyAgreement.PublicKey, salt: String)` function on the original message. It requieres you private key, the other part public key and the salt. You will receive the encrypted message that you can send to the other part with your public key and the salt.

```swift
let salt = "This is our salt"
let message = "This is a top secret message"

let encryptedMessage = message.sealChaChaPoly(
    senderPrivateKey: senderPrivateKey,
    recipientPublicKey: recipientPrivateKey.publicKey,
    salt: salt)
```

### Decrypt a message

To decrypt a message the library has added some extensions to `String` and `Data` classes.

If you want to decrypt some `Data` you will need to use `openChaChaPoly(recipientPrivateKey: P256.KeyAgreement.PrivateKey, senderPublicKey: P256.KeyAgreement.PublicKey, salt: Data)` function on the encrypted message. It requieres you private key, the other part public key and the salt. You will receive the original message.

```swift
let salt = "This is our salt".data(using: .utf8)!

let message = encryptedMessage.openChaChaPoly(
    recipientPrivateKey: recipientPrivateKey,
    senderPublicKey: senderPublicKey,
    salt: salt)
```

If you want to decrypt some `String` you will need to use `openChaChaPoly(recipientPrivateKey: P256.KeyAgreement.PrivateKey, senderPublicKey: P256.KeyAgreement.PublicKey, salt: String)` function on the encrypted message. It requieres you private key, the other part public key and the salt. You will receive the original message.

```swift
let salt = "This is our salt"

let message = encryptedMessage.openChaChaPoly(
    recipientPrivateKey: recipientPrivateKey,
    senderPublicKey: senderPublicKey,
    salt: salt)
```

# Message Authentication Codes

Use hash-based message authentication to create a code with a value that’s dependent on both a block of data and a symmetric cryptographic key. Another party with access to the data and the same secret key can compute the code again and compare it to the original to detect whether the data changed. This serves a purpose similar to digital signing and verification, but depends on a shared symmetric key instead of public-key cryptography.

As with digital signing, the data isn’t hidden by this process.

If you want to compute or validate a message authentication code you can use HMAC. The recipient of the message authentication code will use same HMAC configuration and will need your public key and the salt used for creating the symmetic key. For the full process you will need:

- The message.
- The message authentication code. If you are computing it, you will send it to the other part so it can validate the code. If you are receiving the code, you can validate it.
- Your private key:  A `P256.KeyAgreement.PrivateKey` instance of the private key.
- Public key of the other part: A `P256.KeyAgreement.PublicKey` instance of the public key of other part.
- Your public key: You will need to pass to the other part, so it can compute or validate an authentication code.
- Salt: The salt to use for key derivation. This salt can be shared between sender and recipient.

## HMAC

A hash-based message authentication algorithm.

### Compute a message authentication code

To compute a message authentication code the library has added some extensions to `String` and `Data` classes.

If you want to compute some `Data` you will need to use `authenticationCodeHMAC(senderPrivateKey: P256.KeyAgreement.PrivateKey, recipientPublicKey: P256.KeyAgreement.PublicKey, salt: Data)` function on the message.  It requieres you private key, the other part public key and the salt. You will receive the message authentication code.

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a public message".data(using: .utf8)!

let messageAuthenticationCode = message.authenticationCodeHMAC(
    senderPrivateKey: senderPrivateKey,
    recipientPublicKey: recipientPublicKey,
    salt: salt)
```

If you want to compute some `String` you will need to use `authenticationCodeHMAC(senderPrivateKey: P256.KeyAgreement.PrivateKey, recipientPublicKey: P256.KeyAgreement.PublicKey, salt: Data)` function on the message.  It requieres you private key, the other part public key and the salt. You will receive the message authentication code.

```swift
let salt = "This is our salt"
let message = "This is a public message"

let messageAuthenticationCode = message.authenticationCodeHMAC(
    senderPrivateKey: senderPrivateKey,
    recipientPublicKey: recipientPublicKey,
    salt: salt)
```

### Validate a message authentication code

To validate a message authentication code the library has added some extensions to `String` and `Data` classes.

If you want to validate some `Data` you will need to use `isValidAuthenticationCodeHMAC(recipientPrivateKey: P256.KeyAgreement.PrivateKey, authenticationCode: Data, senderPublicKey: P256.KeyAgreement.PublicKey, salt: Data)` function on the original message.  It requieres you private key, the message authentication code, the other part public key and the salt. You will receive `true` if the original message has not been modified.

```swift
let salt = "This is our salt".data(using: .utf8)!
let message = "This is a public message".data(using: .utf8)!

let isValid = message.isValidAuthenticationCodeHMAC(
    recipientPrivateKey: recipientPrivateKey,
    authenticationCode: authenticationCode,
    senderPublicKey: senderPublicKey,
    salt: salt)
```

If you want to validate some `String` you will need to use `isValidAuthenticationCodeHMAC(recipientPrivateKey: P256.KeyAgreement.PrivateKey, authenticationCode: String, senderPublicKey: P256.KeyAgreement.PublicKey, salt: String)` function on the original message.  It requieres you private key, the message authentication code, the other part public key and the salt. You will receive `true` if the original message has not been modified.

```swift
let salt = "This is our salt"
let message = "This is a public message"

let isValid = message.isValidAuthenticationCodeHMAC(
    recipientPrivateKey: recipientPrivateKey,
    authenticationCode: authenticationCode,
    senderPublicKey: senderPublicKey,
    salt: salt)
```

[badge-languages]: https://img.shields.io/badge/languages-Swift-orange.svg
[badge-pms]: https://img.shields.io/badge/supports-SwiftPM-green.svg
[badge-swift]: http://img.shields.io/badge/swift-5.3-brightgreen.svg
[badge-platforms]: https://img.shields.io/badge/platforms-OSX%2011-lightgrey.svg
