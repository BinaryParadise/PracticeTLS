//
//  Hash.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 17.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import CryptoKit

protocol Hash {
    static func hash(_ m: [UInt8]) -> [UInt8]
    
    static var blockLength: Int { get }
    func update(_ m: [UInt8])
    func finalize() -> [UInt8]
}

extension HashedAuthenticationCode {
    public var bytes: [UInt8] {
        return withUnsafeBytes { r in
            return [UInt8](r.bindMemory(to: UInt8.self))
        }
    }
}

extension SymmetricKey {
    public var bytes: [UInt8] {
        return withUnsafeBytes { r in
            return [UInt8](r.bindMemory(to: UInt8.self))
        }
    }
}
