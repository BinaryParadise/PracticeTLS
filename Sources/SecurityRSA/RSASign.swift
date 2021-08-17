//
//  RSASign.swift
//  GIS2020
//
//  Created by boco on 2020/9/21.
//  Copyright © 2020 gemaojing. All rights reserved.
//

import Foundation
import Security

class RSASign: NSObject {
    
    func RSASingNetCon(data: [UInt8], privateKey: SecKey) -> [UInt8]? {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA1
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            return nil
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey,
                                                    algorithm,
                                                    Data(data) as CFData,
                                                    &error) as Data? else {
            return nil
        }
        return Array(signature)
    }
    
}

