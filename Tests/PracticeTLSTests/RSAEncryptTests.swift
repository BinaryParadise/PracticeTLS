//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import XCTest
import Foundation
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
        let rawData: [UInt8] = try Data(contentsOf: URL(fileURLWithPath: Bundle.certBundle().path(forResource: "Cert/preMaster.bin", ofType: nil)!)).bytes
        
        let identity = PEMFileIdentity(certificateFile: Bundle.certBundle().path(forResource: "Cert/localhost.crt", ofType: nil)!, privateKeyFile: Bundle.certBundle().path(forResource: "Cert/private.pem", ofType: nil)!)
        let rsa = identity?.signer(with: .none) as? RSA
        let decrypted = try rsa?.decrypt(rawData)
        XCTAssertNotEqual(decrypted?.count, 0)
    }
}
