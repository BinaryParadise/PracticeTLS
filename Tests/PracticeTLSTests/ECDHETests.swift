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
@testable import PracticeTLS

class ECDHETests: XCTestCase {
    
    func testECDHEEncrypt() throws {
        let priKey: [UInt8] = "04C473372B66CC92DAE2DDED25A08EEB7541934B893B8A6D975865275D7895E558016E12D7456BCFEAEDD7ECC576AC1AF41BF05E425A7312B3DFEF92B978E8145796AFA3D66644E05B4AC1557C854D8BCB9C36BEDA964CDE66DC52702574553789".uint8Array
        let pubKey: [UInt8] = "04C473372B66CC92DAE2DDED25A08EEB7541934B893B8A6D975865275D7895E558016E12D7456BCFEAEDD7ECC576AC1AF41BF05E425A7312B3DFEF92B978E81457".uint8Array
        let clientPubKey: [UInt8] = "041A4AA3FAD88F8A832C34A52838D275025F7ACE70F3C9A2DB1EA006393A2F3BA1675EE4220B595A0E0CE0DBF5D97FE1B0BB7CCB280FE66383DD9F8D1A30E50A09".uint8Array
        let preMasterSecret: [UInt8] = "0AACE994DD77450FF7B0D240E542DCD736173575077A960D2016A02F0ADD6C37".uint8Array
        let clientRandom: [UInt8] = "9951A5AD1D8461813ABA4458AFE936CC299AB2A6FE998B3CA08C5A28E040DB80".uint8Array
        let serverRandom: [UInt8] = "26E9FF2A03CFFD4E50D487011DF21E26677CF8439E701A3CAC7C554BB7DA86C2".uint8Array
        let masterSecret: [UInt8] = "794FBE34E50C515664D4DB279663028F6CE11692D9F8EB64A803F77835F20711611BC910D3A7120EDC03099FB644A4D4".uint8Array
        
        let ecdh = try ECDHEncryptor(priKey)
        
        XCTAssertEqual(pubKey, ecdh.exportPublickKey())
        
        let shared = try ecdh.keyExchange(clientPubKey)
        XCTAssertEqual(shared, preMasterSecret)
        
        let s = TLSSecurityParameters(.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        s.clientRandom = clientRandom
        s.serverRandom = serverRandom
        s.keyExchange(algorithm: .ecdhe, preMasterSecret: shared)
        
        XCTAssertEqual(masterSecret, s.masterSecret)
        
    }
    
    func testECDH_RSA() throws {
        
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
    
}
