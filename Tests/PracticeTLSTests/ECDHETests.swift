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
@testable import PracticeTLS

class ECDHETests: XCTestCase {
    func testDHE() throws {
        let P = 68987
        let G: Decimal = 235688
        let a = 21215
        let b = 86563
        
        //小红的公钥记作 A，A = G ^ a ( mod P )
        //小明的公钥记作 B，B = G ^ b ( mod P )
        let pkA = pow(G, Int(a)).int % P
        let pkB = pow(G, Int(b)).int % P
        
        let k1 = pow(Decimal(pkA), b).int % P
        let k2 = pow(Decimal(pkB), a).int % P
        XCTAssertEqual(k1, k2)
    }
}
