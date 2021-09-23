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
        let encrypted = record.encrypt(plainData, contentType: .handshake)
        XCTAssertEqual(encrypted, cipherData)
        
        record.decryptor.p = record.encryptor.p
        record.decryptor.p.sequenceNumber = 0
        let decrypted = try record.decrypt(encrypted!, contentType: .applicationData)
        XCTAssertEqual(decrypted, plainData + [ContentType.handshake.rawValue]+[UInt8](repeating: 0, count: 12))
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
        
        let TLSClientHello_512 = "010000dd0303a14716e42b77c47f8d8a1b89cbc9fbb4001bd8396a240dce51970009572400cf000028c02cc02bc024c023c00ac009cca9c030c02fc028c027c014c013cca8009d009c003d003c0035002f0100008cff0100010000000010000e00000b3139322e3136382e322e3100170000000d00140012040308040401050308050501080606010201000500050100000000337400000012000000100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31000b00020100000a00080006001d00170018".uint8Array
        let TLSHelloRetryRequest_88 = "".uint8Array
        let TLSClientHello_512_re = "".uint8Array
        let TLSServerHello_155 = "02000026030326fb1a4aa1d8ead78109f5d865b34a44496b8f079401759084221243df43e07900009c00".uint8Array
        let TLSCertification_1080 = "0b00043400043100042e3082042a30820312a00302010202090098f733ad3aae9573300d06092a864886f70d01010b0500308182310b300906035504061302434e310b300906035504080c025a4a310b300906035504070c02485a311c301a060355040a0c1342696e61727950617261646973652c204c4c433117301506035504030c0e42696e61727950617261646973653122302006092a864886f70d01090116137a6865676562756c6140676d61696c2e636f6d301e170d3231303831303037343131345a170d3232303831303037343131345a308182310b300906035504061302434e310b300906035504080c025a4a310b300906035504070c02485a311c301a060355040a0c1342696e61727950617261646973652c204c4c433117301506035504030c0e42696e61727950617261646973653122302006092a864886f70d01090116137a6865676562756c6140676d61696c2e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100c25ac82e04691e3fa2f38ec1c03a2f6716005b08c87a3728825a0b8f04b3ddf79cb076d0e6c1be678c28b71e7439e7c4b4e2286678794faffb1cef59234790c8234ec2b0c298008072b128cb393fd1dcad17260b3dc751802f9fa12439060a2bdd09a5c288d11f150fe4a4e5f7479fb5523f1b2093b731c87b039093a72ef16e28e77d606031ae53596b55a1a2caa42c42b359dfc1e83be22ff962b20632520b50d8a187bec36b6b6b71fe3d6453b0d09b1c3003cd7dfab86da50ff9aca82d3cb65d46f724cad49ae2e4c941d7e0701dc8f5dbba5e2838e9abbc9dadcc42b5f97316e793abfc297370fb914ac56ce65b6bc58c3d19e3c46965a93642df3525070203010001a381a030819d301d0603551d0e0416041415f98d855fb1b2e32a914a16be84fed9f78b8472301f0603551d2304183016801415f98d855fb1b2e32a914a16be84fed9f78b847230090603551d1304023000300b0603551d0f0404030205a030150603551d11040e300c820a746573742e6c6f63616c302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465300d06092a864886f70d01010b0500038201010099bfdcad9da75e4fb1fcfb3d26af944d1524f2e938e9a6e837ac9fbdb151497355b3ba8ecf6f1677c01b9ab0364de8f585828b12bf197b3d85f9ee7ee33995c5d0f4ffaa8485674c0da0981f395a72dca94362530e882668ba4b335f73855973ffa7b5cf0aac4b59a021e3a97da64785d52169f735721338950b9dc6c0479583596147266de65ac9f9810860e08093e83bbbeb1b2fbdfa8ec68b1b75c0419edc5b041a0d9ad085197ef164d16e9781cdec24273540b0b80012a4bac3469f9c77e1e9e72f69bd6bd94a87e622737c0ce419ca6992df5b9f379dbc55d72e6ad8ede4288fa61c2005d042cea62800fceee30a27d745b1c8cc0d6c1d8c07c6792460".uint8Array
        
        let TLSServerHelloDone_4 = "0e000000".uint8Array
        let TLSClientKeyExchange_262 = "1000010201008d34961b019f57a2fe2c034fe5bee2487693d295201782a33492cfb5ab7e5eaa24405c7e8d1e683a564b508b1b0cddc468566b88a9fb74881fcb29d71c526ba8ef585ff9ca0fdf32f80c80ecc8bab0c084336519e09555fe54034aa0838c5dfc1be114ed69289c404da8085dfade163e8dd3ca9d4291abe3d8210bab5cf581ce960c12d8bf6163c32dde4d82c3e2c7bd804eb18daed21433970dbb02a121f74b95f4f28a09d5264a19c42ca5f24ae5ec10f1b5240d11737c999fad801257d82325c611e068fcfde6fbae1b050935e96de7309c0c8986c90d336ec0fcc4cb09e6d401ab87f0b4ef6a7e8290057f87c3c357d6d3827d267eb1b1a497271aade8fd".uint8Array
        
        var handshakeData = TLSClientHello_512
        if TLSHelloRetryRequest_88.count > 0 {
            let hashLength = HashAlgorithm.sha256.hashLength
            let hashValue = HashAlgorithm.sha256.hashFunction(handshakeData)
            
            handshakeData = [TLSHandshakeType.messageHash.rawValue, 0, 0, UInt8(hashLength)] + hashValue
            
            
            handshakeData.append(contentsOf: TLSHelloRetryRequest_88)
        }
        
        //handshakeData.append(contentsOf: TLSClientHello_512_re)
        handshakeData.write(TLSServerHello_155)
        handshakeData.write(TLSCertification_1080)
        handshakeData.write(TLSServerHelloDone_4)
        handshakeData.write(TLSClientKeyExchange_262)
        
        let transcriptHash = HashAlgorithm.sha256.hashFunction("1400000c2cef3ce9e7c942c3ef74d020".uint8Array)
        
        let newTranscriptHash = HashAlgorithm.sha256.hashFunction(handshakeData)
        
        XCTAssertEqual(transcriptHash, newTranscriptHash)
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
