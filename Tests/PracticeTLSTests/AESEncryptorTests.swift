//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/16.
//

import XCTest
import Foundation
import CryptoSwift
@testable import PracticeTLS

class AESEncryptorTests: XCTestCase {
    func testEncrypt() throws {
        let cipherData:[UInt8] = [0xc0, 0xae, 0x12, 0x9b, 0x83, 0xc7, 0x2e, 0xac, 0x8d, 0x63, 0x9a, 0x2c, 0x51, 0xa9, 0x2c, 0x92, 0x6f, 0x97, 0x19, 0x30, 0x97, 0x1d, 0xd6, 0x5f, 0x38, 0xa2, 0xab, 0x04, 0x40, 0xfd, 0x3a, 0xa6, 0x9c, 0x62, 0x18, 0x06, 0x7c, 0x5d, 0x9f, 0xd5, 0x7b, 0x51, 0xa2, 0xc5, 0xde, 0x1d, 0x17, 0x7e, ]
        let masterKey:[UInt8] = [
            0x7d, 0x18, 0xe5, 0xcd, 0x43, 0x9c, 0x5c, 0x24, 0x0e, 0xcc, 0xae, 0x77, 0xba, 0xe0, 0xdf, 0xdb, 0xcb, 0xff, 0xa5, 0x37, 0xb9, 0x7b, 0xad, 0x5f, 0xbe, 0x31, 0x7f, 0x6a, 0xbd, 0xa5, 0xa2, 0x85,
        ]
        let iv: [UInt8] = [
            0xf5, 0x94, 0x19, 0xf2, 0x33, 0x20, 0x1d, 0x94, 0x9e, 0x08, 0x34, 0x2b, 0x28, 0xeb, 0x8d, 0x16,
        ]
        
        let aes = try CryptoSwift.AES(key: masterKey, blockMode: CBC(iv: iv), padding: .zeroPadding)
        let decrypted = try aes.decrypt(cipherData)
        let n = Padding.pkcs7.add(to: decrypted, blockSize: 16)
        XCTAssertEqual(cipherData, decrypted)
        
        let a = PracticeTLS.AES(key: masterKey, bitSize: .aes256, encrypt: false)
        var d = [UInt8](repeating: 0, count: cipherData.count)
        a.update(indata: cipherData, outdata: &d)
        XCTAssert(d == nil)
    }
    
    func test2() {
        let cipherData: [UInt8] = [0x14, 0x00, 0x00, 0x0c, 0x99, 0x90, 0x76, 0xe7, 0x10, 0x4e, 0x21, 0xc5, 0x0d, 0x6f, 0x94, 0x44, 0x8a, 0x94, 0x0d, 0x5f, 0x78, 0x7b, 0x03, 0xd1, 0xea, 0xa4, 0xcc, 0x7f, 0x3f, 0xb9, 0xd7, 0xc3, 0xd9, 0x6c, 0xf1, 0xda, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,]
        let iv: [UInt8] = [0x55, 0x6b, 0x4d, 0x76, 0xe6, 0x90, 0x91, 0x77, 0x39, 0xf5, 0xa8, 0x04, 0x26, 0xda, 0x0e, 0x37, ]
    }
}
