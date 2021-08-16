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
    
    func RSASingNetCon(value:String) -> String {
        let ts = Date().timeIntervalSince1970 * 1000000
         let signString = "\(kRSAPublicKey)&ts=\(Int64(ts))"
                let pathPrivate = Bundle.main.path(forResource: "private_key", ofType: "p12")
                let pathPublic  = Bundle.main.path(forResource: "public_key", ofType: "der")

                let privateUrl = URL(fileURLWithPath: pathPrivate!)
                let privateData = try! Data(contentsOf: privateUrl)
                let privatePwd = "Boco123,"
                let options = [kSecImportExportPassphrase as String: privatePwd]
                var rawItems: CFArray?
                let status = SecPKCS12Import(privateData as CFData, options as CFDictionary, &rawItems)
                guard status == errSecSuccess else { return "0"}
                let items = rawItems! as! Array<Dictionary<String, Any>>
                let firstItem = items[0]
                let identity = firstItem[kSecImportItemIdentity as String] as! SecIdentity?

                var privateKey: SecKey?
                let status1 = SecIdentityCopyPrivateKey(identity!, &privateKey)
                guard status1 == errSecSuccess else { return "0" }
                var signedStr = value // ""
                  // iOS10以后，系统原生实现方式
                    let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA1
                    guard SecKeyIsAlgorithmSupported(privateKey!, .sign, algorithm) else {
                        return "0"
                    }
                    var error: Unmanaged<CFError>?
                    guard let signature = SecKeyCreateSignature(privateKey!,
                                                                algorithm,
                                                                signString.data(using: .utf8)! as CFData,
                                                                &error) as Data? else {
                                                                    return "0"
                    }
                    signedStr = signature.base64EncodedString()
               return  signedStr
    }
    
}

