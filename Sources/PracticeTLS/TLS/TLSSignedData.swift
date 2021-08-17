//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/11.
//

import Foundation

public enum HashAlgorithm : UInt8 {
    case none   = 0
    case md5    = 1
    case sha1   = 2
    case sha224 = 3
    case sha256 = 4
    case sha384 = 5
    case sha512 = 6
    
    var macAlgorithm: MACAlgorithm {
        switch self {
        case .md5:
            return .hmac_md5
            
        case .sha1:
            return .hmac_sha1
            
        case .sha256:
            return .hmac_sha256
            
        case .sha384:
            return .hmac_sha384
            
        case .sha512:
            return .hmac_sha512
            
        default:
            fatalError("HMAC with hash function \(self) is not supported.")
        }
    }
    
    var hashLength: Int {
        return macAlgorithm.size
    }
    
    typealias HashFunction = ([UInt8]) -> [UInt8]
    var hashFunction: HashFunction {
        switch self {
        case .sha1:
            return Hash_SHA1
        case .sha256:
            return Hash_SHA256
            
        case .sha384:
            return Hash_SHA384
            
        default:
            fatalError("Unsupported hash function \(self)")
        }
    }

    var oid: OID {
        switch self
        {
        case .sha1:
            return OID.sha1
            
        case .sha256:
            return OID.sha256
            
        default:
            fatalError("Unsupported hash algorithm \(self)")
        }
    }
    
    init?(oid: OID)
    {
        switch oid
        {
        case .sha256:
            self = .sha256
            
        default:
            return nil
        }
    }
}
enum SignatureAlgorithm : UInt8 {
    case anonymous  = 0
    case rsa        = 1
    case dsa        = 2
    case ecdsa      = 3
}

struct TLSSignedData: Streamable {
    var hashAlgorithm : HashAlgorithm = .sha256
    var signatureAlgorithm : SignatureAlgorithm = .rsa
    
    var signature : [UInt8] = []
    
    init(data: [UInt8]) {
        do {
            try signature = TLSSessionManager.shared.identity.signer(with: hashAlgorithm).sign(data: data)
        } catch {
            LogError("签名失败: \(error)")
        }
    }
    
    func dataWithBytes() -> [UInt8] {
        var data:[UInt8] = []
        data.append(hashAlgorithm.rawValue)
        data.append(signatureAlgorithm.rawValue)
        data.append(contentsOf: UInt16(signature.count).bytes())
        data.append(contentsOf: signature)
        return data
    }
}
