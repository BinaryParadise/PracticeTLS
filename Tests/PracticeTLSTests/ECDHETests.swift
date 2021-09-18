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
        XCTFail()
    }
    
    // 使用封装类加解密
    func testTLS1_3_Encrypt() throws {
        let ecPriKey = "04B136511690172359CE3F791007FF923368810FDB7B9773C76B7E0D862409D929F0BB0C6AF2548F2976AC6368276B6906DF9A30820A317F3D179EFD3054471CBE37D57B41566174B41BE85D8CDE79871573CD475BB06E73054AC602EB3BB4566A".uint8Array
        let ecPubKey = "04B136511690172359CE3F791007FF923368810FDB7B9773C76B7E0D862409D929F0BB0C6AF2548F2976AC6368276B6906DF9A30820A317F3D179EFD3054471CBE".uint8Array
        let clientPubKey = [4] +  "49E017421BECF01F4AB57030996848751EB05EF2514DB0D2900EEE77006C479D07EBEFACE94935B4B58BF1E63D2C769ABCC90FF7849608DF1A9F7B2A714969F0".uint8Array
        let sharedSecret = "14BF4D914418932424D3BCBDE670C011828D921A63736F1B180FDFD59522B807".uint8Array
        
        let derivedSecret = "126EAE97FB29828F6D464061FF29975DC7CDEA9D60B66E1D24F5153D23C95C56".uint8Array
        let transcriptHash = "A42B3CCB8868841BD9753A7A7248691ADDDA828564B69EEE5657A2FA49F6405D".uint8Array
        let handshakeSecret1 = "C5D53B7E43A62D76D881F45A8849EC2AF12DEBFE252B96E5F79C75D19B5F4EC3".uint8Array
        let clientHandshakeSecret = "DF9A4E9350C695D02B597F78A43CF3A8390BC11F199021D937E251226C2100BD".uint8Array
        let writeKey = "495BBF6EE33DB27471A84EE297575E9A".uint8Array
        let writeIV = "18F08C40A31D55C80F1C75CB".uint8Array
        let readKey = "85223681390CD1CCDBB05B96019276A3".uint8Array
        let readIV = "B3BC1F1DB051CE24EB970E85".uint8Array
        let currentIV = "18F08C40A31D55C80F1C75CB".uint8Array

        let plainData = "080000020000".uint8Array
        let additionalData = "1703030023".uint8Array
        let cipherData = "A1A421FE6F31DCAC6A4652F07263DD1445B48D13E1696381BD281AA3AE3B915B54ED45".uint8Array
//13E1696381BD281AA3AE3B915B54ED45
        let conn = TLSConnection(GCDAsyncSocket())
        let record = TLS1_3.RecordLayer(conn)
        conn.record = record
        record.setPendingSecurityParametersForCipherSuite(.TLS_AES_128_GCM_SHA256)
        conn.keyExchange = .ecdha(try .init(ecPriKey, group: .secp256r1))
        conn.preMasterKey = clientPubKey
        
        record.derivedSecret(transcriptHash)
        
        XCTAssertEqual(record.s.masterSecret, sharedSecret)
                    
        XCTAssertEqual(record.handshakeState.earlySecret, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a".uint8Array)
        
        XCTAssertEqual(record.handshakeState.handshakeSecret, handshakeSecret1)
                        
        XCTAssertEqual(record.handshakeState.clientHandshakeTrafficSecret, clientHandshakeSecret)
        
        XCTAssertEqual(writeKey, record.encryptor.p.key)
        
        XCTAssertEqual(writeIV, record.encryptor.p.iv)
        
        XCTAssertEqual(readKey, record.decryptor.p.key)
        XCTAssertEqual(readIV, record.decryptor.p.iv)
        
        XCTAssertEqual(currentIV, record.encryptor.p.currentIV)
        let encrypted = record.encrypt(plainData, contentType: .handshake(.encryptedExtensions))
        XCTAssertEqual(encrypted, cipherData)
        
        record.decryptor.p = record.encryptor.p
        record.decryptor.p.sequenceNumber = 0
        let decrypted = try record.decrypt(encrypted!, contentType: .applicationData)
        XCTAssertEqual(decrypted, plainData + [ContentType.handeshake.rawValue]+[UInt8](repeating: 0, count: 12))
    }
    
    func testEncrypt() throws {
        let cipherData = "ACC38FA6984DAF133D663AAC91D2E74B3DEB28".uint8Array
        let additionalData = "1703030013".uint8Array
        let curReadIV = "85393AF3C9C639D42F8FDCEE".uint8Array
        
        let readKey = "9A56B41C32A72EBF5FB3AF206015ABAC".uint8Array
        let readIV = "85393AF3C9C639D42F8FDCEE".uint8Array
        
        var ep = TLS1_3.RecordLayer.Decryptor(p: TLS1_3.RecordLayer.EncryptionParameters(cipherSuiteDecriptor: TLSCipherSuiteDescriptionDictionary[.TLS_AES_128_GCM_SHA256]!, key: readKey, iv: readIV))

        XCTAssertEqual(curReadIV, ep.p.currentIV)
        
        let decrypted = try ep.decrypt(cipherData, contentType: .applicationData)
        
        XCTAssertNotNil(decrypted)
    }
    
    func testCalculatTranscript() throws {
        
        let TLSClientHello_512 = "010001fc0303b1ac6624832518cdf8cc9187cb68bef24956653392692eaab71505e281c04ea7200bb71d41c4e901cec69223aa75dd9b8dd62c91c456bfed974e63684acb8bd9800024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a0100018f00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00203c0203f8344c0b46935f26ba64631c3428b03017dfa3e56731d0845d4aade33800170041044b073e262d760ca8460d67e4ba19856e87489aad5ca3aa93847017b6cc26c5ae987cf819f75c30a412dc1eb19d2df96218d4937aec28432e2c59bf2e32d4eb9f002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c000240010015009d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".uint8Array
        let TLSHelloRetryRequest_88 = "".uint8Array
        let TLSClientHello_512_re = "010001fc03039f6df04ed0d403b8fc50f503025a7e35ddbe463271868a361201d760e1daaad52074b02c7ec8cd09a14910418034bd4f792e217ae6b44fb2e1d1a6c6a43d5315c30036fafa130113021303c02cc02bcca9c030c02fcca8c024c023c00ac009c028c027c014c013009d009c003d003c0035002fc008c012000a0100017dbaba000000170000ff01000100000a000c000a9a9a001d001700180019000b000201000010000e000c02683208687474702f312e31000500050100000000000d0018001604030804040105030203080508050501080606010201001200000033004700450017004104fcba87b587e504c6d7f57ace25464eefee2a0e9bd700e0e94dbea09a95e9025c7c11b38685e64e160ee32d8281a1ea9114be4a626048f796b99f4235a8745ed8002d00020101002b000b0a7a7a03040303030203014a4a000100001500b60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".uint8Array
        let TLSServerHello_155 = "02000097030326f5cf3614eeccccde667ce8e2e9dd2292e44958d7a8352ca409c55bd1cfb5bc200bb71d41c4e901cec69223aa75dd9b8dd62c91c456bfed974e63684acb8bd980130100004f002b0002030400330045001700410484dfa417b03553d58c90111ce99baa8418f392a55519dd9a38290414e8cec96f3e7b03b7e97e9189fc02e2cee3eafbf34ed54ac107417385af6cde4db4ff9a99".uint8Array
        
        var handshakeData = TLSClientHello_512
        if TLSHelloRetryRequest_88.count > 0 {
            let hashLength = HashAlgorithm.sha256.hashLength
            let hashValue = HashAlgorithm.sha256.hashFunction(handshakeData)
            
            handshakeData = [TLSHandshakeType.messageHash.rawValue, 0, 0, UInt8(hashLength)] + hashValue
            
            
            handshakeData.append(contentsOf: TLSHelloRetryRequest_88)
        }
        
        //handshakeData.append(contentsOf: TLSClientHello_512_re)
        handshakeData.append(contentsOf: TLSServerHello_155)
        
        let transcriptHash = "e8c3df9b33ee5df3e774e78f59ebc4c12f14b604d477b33d64fe81f30d7ff59e".uint8Array
        
        let newTranscriptHash = HashAlgorithm.sha256.hashFunction(handshakeData)
        
        XCTAssertEqual(transcriptHash, newTranscriptHash)
    }
    
    func testKeyLog() throws {
        let priKey = "0484dfa417b03553d58c90111ce99baa8418f392a55519dd9a38290414e8cec96f3e7b03b7e97e9189fc02e2cee3eafbf34ed54ac107417385af6cde4db4ff9a99c424f2425c9589309ef09e69c7ae79e977910257630de97bb42d755b9a4e6eda".uint8Array
        let serverPubKey = "0484dfa417b03553d58c90111ce99baa8418f392a55519dd9a38290414e8cec96f3e7b03b7e97e9189fc02e2cee3eafbf34ed54ac107417385af6cde4db4ff9a99".uint8Array
        let clientPubKey = "044b073e262d760ca8460d67e4ba19856e87489aad5ca3aa93847017b6cc26c5ae987cf819f75c30a412dc1eb19d2df96218d4937aec28432e2c59bf2e32d4eb9f".uint8Array
        let clientRandom = "b1ac6624832518cdf8cc9187cb68bef24956653392692eaab71505e281c04ea7".uint8Array
        let serverRandom = "26f5cf3614eeccccde667ce8e2e9dd2292e44958d7a8352ca409c55bd1cfb5bc".uint8Array
        let transcriptHash = "e8c3df9b33ee5df3e774e78f59ebc4c12f14b604d477b33d64fe81f30d7ff59e".uint8Array
        let clientHandshakeTrafficSecret = "cdbe911a05787ac058547b12a10ccfc8f914c32c7b096848400ccd78c38a9d1c".uint8Array
        let serverHandshakeTrafficSecret = "ab300d5f4ee2f389c029a2e59af4de94fc0a5fc9ced39d7e7f9a571d4188acbc".uint8Array
        
        let conn = TLSConnection(GCDAsyncSocket())
        let record = TLS1_3.RecordLayer(conn)
        conn.record = record
        record.setPendingSecurityParametersForCipherSuite(.TLS_AES_128_GCM_SHA256)
        conn.keyExchange = .ecdha(try .init(priKey, group: .secp256r1))
        conn.preMasterKey = clientPubKey
        
        record.derivedSecret(transcriptHash)
        
        XCTAssertEqual(record.handshakeState.clientHandshakeTrafficSecret?.toHexString(), "71677573cac022701a202664e856be1782f743f2287381a37fd9e127c5a4595c")
        XCTAssertEqual(record.handshakeState.serverHandshakeTrafficSecret?.toHexString(), "45775de7afebfc26d2a1de6b5ff895d6730c023d1d80085f2b9591b238db6dc3")
    }
}
