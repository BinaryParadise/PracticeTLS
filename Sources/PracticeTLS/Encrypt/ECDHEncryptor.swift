//
//  ECDHEncryptor.swift
//  
//
//  Created by Rake Yang on 2021/9/7.
//

import Foundation
import CryptoKit

public class ECDHEncryptor {
    var privateKeyData: [UInt8]
    let namedGroup: NamedGroup
    
    func keyAttr(pub: Bool) -> CFDictionary {
        return [kSecAttrKeyClass: pub ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
                kSecReturnPersistentRef: true,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom] as CFDictionary
    }
    
    public init(_ priKeyData: [UInt8]? = nil, group: NamedGroup = .x25519) throws {
        self.namedGroup = group
        if let priKeyData = priKeyData {
            privateKeyData = priKeyData
        } else {
            if group == .secp256r1 {
                privateKeyData = P256.KeyAgreement.PrivateKey().x963Representation.bytes
            } else if group == .x25519 {
                privateKeyData = Curve25519.KeyAgreement.PrivateKey().rawRepresentation.bytes
            } else {
                fatalError("Unsupport NameGroup: \(group)")
            }
        }
    }
    
    func exportPublickKey() -> [UInt8] {
        do {
            if namedGroup == .x25519 {
                let priKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
                return Array(priKey.publicKey.rawRepresentation.bytes)
            } else if namedGroup == .secp256r1 {
                let priKey = try P256.KeyAgreement.PrivateKey(x963Representation: privateKeyData)
                return Array(priKey.publicKey.x963Representation)
            } else {
                fatalError("Unsupport namedGroup: \(namedGroup)")
            }
        } catch {
            fatalError(("\(error)"))
        }
    }
    
    public func keyExchange(_ pubKey: [UInt8]) throws -> [UInt8] {
        if namedGroup == .x25519 {
            let priKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let sharedSecret = try priKey.sharedSecretFromKeyAgreement(with: .init(rawRepresentation: pubKey))
            return sharedSecret.withUnsafeBytes { r in
                return [UInt8](r.bindMemory(to: UInt8.self))
            }
        } else if namedGroup == .secp256r1 {
            // CryptoKit
            let me = try P256.KeyAgreement.PrivateKey(x963Representation: privateKeyData)
            let sharedSecret = try me.sharedSecretFromKeyAgreement(with: .init(x963Representation: pubKey))
            return sharedSecret.withUnsafeBytes { r in
                return [UInt8](r.bindMemory(to: UInt8.self))
            }
        }
        return []
    }
}
