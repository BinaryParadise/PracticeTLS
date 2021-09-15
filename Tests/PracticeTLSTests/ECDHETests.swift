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
@testable import PracticeTLS

class ECDHETests: XCTestCase {
    
    func testECDH_RSA_Sign() throws {
        let rsa = try RSAEncryptor()
        let clientRandom = "08baba916f7f01ffaa86d1a227125a7cac8925a2668ceaf84aba95609d419154".uint8Array
        let serverRandom = "26e86c58b27eb49ab5bfd4bb17e54d2cfb161d03b7376b099d264a399825e454".uint8Array
        let param: [UInt8] = [0x03,0x00,0x17,0x41,0x04,0xb5,0xa7,0x58,0xee,0x66,0xee,0xc5,0xf2,0x64,0x17,0x40,
                          0xa6,0x87,0xcb,0x11,0x49,0x98,0x46,0x8e,0x9b,0x8a,0x9e,0x56,0xec,0x24,0x1a,0x9f,
                          0x17,0x24,0xce,0x86,0x5b,0xf7,0xed,0xd6,0x8c,0xb4,0xf5,0x41,0x55,0xff,0x04,0xc4,
                          0x2c,0x26,0xa5,0x6f,0xf1,0xae,0x50,0xe6,0x81,0x15,0xeb,0x9c,0xbb,0xf9,0xf4,0x93,
                          0x9c,0x74,0x1f,0x70,0xce]
        
        let data = clientRandom+serverRandom+param
        let signture =  "98610920c031115bc874a67dad3e9b02e20b0dbf12d4a274714278d0aa82e0308800de240bf54db15d572001137dc7bdceba9affd5d725079c9c164fd554c4195f33e53783819c352837ad260341860f56358f3e0d68772c25720b4041a0a75f556d5c884f9898f8274b57db6a8018cbed7433d245626edc238c67c76a9dd753c181655cc362decf6823060d6ffc5e025545392df52e3496dde2cbc36175d61418d0c5fee138ae926c81b868b3ec78de0e673edc8ff4b3bb5f46554518087193ebfd40e493564a68f344d27703e9032ce41c5ae4e9fbe210868193e4c61995083a87a7aaa860879e8d5ce87b18f0053768a3e3586c9afe0a7ac7f6b090d03183".uint8Array
                
        let verfiy = try rsa.verify(signed: data, signature: signture)
        XCTAssert(verfiy)
    }
    
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
        XCTFail()
    }
}
