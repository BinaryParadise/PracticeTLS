//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/9/23.
//

import Foundation

//https://blog.csdn.net/u010983881/article/details/77503519

class BigInteger {
    var bits: [UInt8]
    
    init(_ data: [UInt8]) {
        bits = data
    }
    
    init(_ data: String) {
        bits = Array(data.bytes)
    }
    
    static func *(lfs: BigInteger, rfs: BigInteger) -> BigInteger {
        return BigInteger(karatsuba(1024, 2048).bytes)
    }
    
    /**
     * Karatsuba乘法
     */
    class func karatsuba(_ num1: Int64, _ num2: Int64) -> Int64 {
        //递归终止条件
        if(num1 < 10 || num2 < 10) {
            return num1 * num2
        }

        // 计算拆分长度
        let size1 = String(num1).count
        let size2 = String(num2).count
        let halfN = max(size1, size2) / 2
        
        let s1 = String(num1)
        let s2 = String(num2)

        /* 拆分为a, b, c, d */
        let a = Int64(s1[s1.startIndex..<s1.index(s1.startIndex, offsetBy: size1 - halfN)]) ?? 0
        let b = Int64(s1[s1.index(s1.startIndex, offsetBy: size1 - halfN)...]) ?? 0
        let c = Int64(s2[s2.startIndex..<s2.index(s2.startIndex, offsetBy: size2 - halfN)]) ?? 0
        let d = Int64(s2[s2.index(s2.startIndex, offsetBy: size2 - halfN)...]) ?? 0

        // 计算z2, z0, z1, 此处的乘法使用递归
        let z2 = karatsuba(a, c)
        let z0 = karatsuba(b, d)
        let z1 = karatsuba((a + b), (c + d)) - z0 - z2
        let r1 = Int64(truncating: pow(10, 2 * halfN) as NSNumber)
        let r2 = Int64(truncating: pow(10, halfN) as NSNumber)
        
        return Int64(z2 * r1 + z1 * r2  + z0)
    }

}
