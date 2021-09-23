//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/27.
//

import Foundation
import XCTest
import Foundation
import CryptoSwift
import SecurityRSA
import CommonCrypto
import CryptoKit
import CocoaAsyncSocket
@testable import PracticeTLS

class ECDHETests: XCTestCase {
    func testECDH_Curve() throws {
        let attributes = [
            kSecAttrKeySizeInBits: 256,
            SecKeyKeyExchangeParameter.requestedSize.rawValue: 32,
            kSecAttrKeyType: kSecAttrKeyTypeEC,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]] as CFDictionary
                        
        
        let types = [kSecAttrKeyTypeECSECPrimeRandom]
        try types.forEach { t in
            let attributes = [
                kSecAttrKeySizeInBits: 256,
                SecKeyKeyExchangeParameter.requestedSize.rawValue: 32,
                kSecAttrKeyType: t,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]] as CFDictionary
            var error: Unmanaged<CFError>?
            
            let pk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data("04eb7c42bf8317508adc0e2f26902c64636cdeb570695d830cab6086c6f34f39".uint8Array))

            
            print("\(t) \(pk) \(error)")
                        
            if let privateKey = SecKeyCreateRandomKey(attributes, &error) {
                let pubKey = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(privateKey)!, &error)
                let prk = Curve25519.KeyAgreement.PrivateKey()
                print("\(prk)")
                let publicKey = SecKeyCreateWithData(pubKey!, [kSecAttrType: t,
                                                        kSecReturnPersistentRef: true,
                                                        kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, &error)
                print("\(t as String) => \(publicKey) \(error)")
            }
        }
    }
    
    func testKeyLog() throws {
        let handshakeSecret = "6F8063C71AD6DBDD12350FE0E884E960654A90C456570D50498EC085A1C572E1".uint8Array
        let clientTrafficeSecret = "60EC2A9E8F56EAFE8EABA14A1A72F361AAAF916C2474561D417016A2C41BA2DC".uint8Array
        let readKey = "C61D9580779142C27BA1903BA5D0FF3E".uint8Array
        let readIV = "110D22ADC323BC871DC3CD22".uint8Array
        
        let cipherDesc = TLSCipherSuiteDescriptionDictionary[.TLS_AES_128_GCM_SHA256]
        let hs = TLS1_3.HandshakeState(.sha256).neweEncryptionParameters(withTrafficSecret: clientTrafficeSecret, cipherSuite: .TLS_AES_128_GCM_SHA256)
        
        XCTAssertEqual(hs.key, readKey)
        XCTAssertEqual(hs.iv, readIV)
    }
}
