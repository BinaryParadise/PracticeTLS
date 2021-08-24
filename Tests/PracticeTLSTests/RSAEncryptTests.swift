//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import XCTest
import Foundation
import SecurityRSA

@testable import PracticeTLS

class RSAEncryptTests: XCTestCase {
    override func setUp() {
        var ctx = BigIntContext()
        ctx.open()
        _ = BigIntContext.setContext(ctx)
    }
    
    override func tearDown() {
        _ = BigIntContext.setContext(nil)
    }
    
    func testOpenSSLRSAUtl() throws {
        let task = Process()
        task.launchPath = "/usr/bin/openssl"
        task.currentDirectoryPath = Bundle(for: Self.self).bundlePath
        task.arguments = ["rsautl", "-raw", "-decrypt", "-in", Bundle.certBundle().path(forResource: "Cert/preMaster.bin", ofType: nil)!, "-inkey", Bundle.certBundle().path(forResource: "Cert/private.key", ofType: nil)!, "-out", "../output.bin"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        task.launch()
        task.waitUntilExit()
        
        let bytes = try Data(contentsOf: URL(fileURLWithPath: "output.bin")).bytes
        XCTAssert(bytes.count > 0)
    }
    
    func testPreMaster() throws {
        
        let encryptedPreMasterSecret:[UInt8] = [0x3d, 0xb0, 0x66, 0xf7, 0x7f, 0x75, 0xcd, 0x7a, 0xcd, 0xa4, 0xcf, 0xb2, 0xbe, 0x87, 0x96, 0x8d, 0x0a, 0x70, 0x18, 0x67, 0x75, 0xd0, 0xeb, 0x34, 0x6a, 0xf4, 0x57, 0x3c, 0x7b, 0x95, 0x87, 0x29, 0xcc, 0xa8, 0x4c, 0x92, 0x00, 0x40, 0x1f, 0x3e, 0x07, 0x7b, 0x5b, 0x1b, 0x72, 0xc3, 0xe1, 0x32, 0x37, 0x85, 0xd2, 0x9a, 0x58, 0x5c, 0xad, 0x54, 0x91, 0x41, 0x3f, 0x62, 0xac, 0x35, 0x0c, 0x35, 0xc6, 0x33, 0x87, 0x88, 0x00, 0xba, 0x40, 0x41, 0xb3, 0xff, 0x61, 0x1d, 0xb5, 0x2b, 0x1b, 0x52, 0x57, 0x2b, 0x0a, 0xe7, 0x16, 0x31, 0x2c, 0x51, 0xbc, 0xd4, 0x1a, 0x6e, 0x15, 0x00, 0x7d, 0xdc, 0xb6, 0x1e, 0x38, 0xf7, 0x0a, 0xe6, 0xf9, 0xe4, 0x19, 0x22, 0xdb, 0xf4, 0x07, 0x97, 0x07, 0x3d, 0x83, 0x2d, 0x30, 0xa2, 0x98, 0x82, 0x11, 0x9c, 0xec, 0x9b, 0xd0, 0x49, 0x61, 0x95, 0x99, 0xfa, 0x69, 0xbf, 0x99, 0x93, 0x55, 0xf8, 0x73, 0x96, 0x28, 0x53, 0x51, 0x5d, 0x04, 0x14, 0xc4, 0x33, 0xea, 0x37, 0x77, 0x50, 0x3d, 0xd8, 0x97, 0x49, 0x04, 0x1e, 0xfa, 0x14, 0x66, 0x4f, 0x52, 0xb2, 0x87, 0xb9, 0x7e, 0x40, 0x63, 0x96, 0x88, 0xbe, 0x2a, 0xf6, 0x33, 0xc2, 0xf7, 0x2f, 0xe9, 0x59, 0xb8, 0x91, 0x5a, 0x01, 0xe8, 0xe3, 0x49, 0x00, 0x3a, 0xfb, 0x66, 0x32, 0x37, 0xe5, 0x90, 0xcb, 0x0c, 0x4f, 0x9e, 0x67, 0x16, 0xd7, 0x0d, 0x6d, 0xce, 0x72, 0xaf, 0xdf, 0x4e, 0xce, 0x72, 0xac, 0xa3, 0x9b, 0x50, 0x75, 0x9a, 0x88, 0xcb, 0x53, 0xdc, 0x3d, 0xd7, 0x9c, 0x4f, 0xd9, 0x07, 0x37, 0xd7, 0x4c, 0xd7, 0x7b, 0x95, 0x8b, 0x9a, 0xf5, 0xdf, 0x20, 0xeb, 0xa7, 0x33, 0x62, 0x54, 0xed, 0xd4, 0x73, 0xa5, 0xff, 0x54, 0x06, 0x70, 0xb5, 0x8d, 0xae, 0x51, 0x77, 0xd6, 0x03, 0x83, 0x5f, ]
        let preMasterSecret:[UInt8] = [0x03, 0x03, 0x3f, 0xbf, 0x51, 0x53, 0xbe, 0x71, 0x00, 0x79, 0x1a, 0x11, 0x39, 0x60, 0x7b, 0x3d, 0xdb, 0x92, 0x60, 0xbc, 0xc4, 0xa0, 0x4a, 0x96, 0xa8, 0x70, 0xab, 0x54, 0x06, 0x23, 0x10, 0x63, 0xdb, 0xea, 0xd3, 0x46, 0xe6, 0xa1, 0xa7, 0xab, 0xac, 0x3d, 0x13, 0x9b, 0x76, 0x6b, 0x0a, 0x65, ]
        
        let rsa = RSAEncryptor()
        let decrypted = try rsa.decryptData(data: encryptedPreMasterSecret)
        XCTAssertEqual(decrypted, preMasterSecret)
    }
}
