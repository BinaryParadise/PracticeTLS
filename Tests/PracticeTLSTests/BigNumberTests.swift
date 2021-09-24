//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/9/23.
//

import Foundation
import XCTest
@testable import PracticeTLS

//https://zhuanlan.zhihu.com/p/144813558
class BigNumberTests: XCTestCase {
    
    func testCalculate() throws {
        let bi1 = BInt("1234567890123")
        let bi2 = BInt("9876543210123")
            
        let bir = bi1 * bi2
        
        XCTAssertEqual(bir.description, "12193263112630193565315129")
    }
}
