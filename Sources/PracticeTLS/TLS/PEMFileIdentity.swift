//
//  PEMFileIdentity.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 02.07.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

public class PEMFileIdentity
{
    public var certificateChain: [X509.Certificate]
    public func signer(with hashAlgorithm: HashAlgorithm) -> Signing {
        switch _signing {
        case is RSA:
            var rsa = _signing as! RSA
            switch rsa.algorithm {
            case .rsa_pkcs1(hash: _):
                rsa.algorithm = .rsa_pkcs1(hash: hashAlgorithm)
            case .rsassa_pss(hash: _, saltLength: let saltLength):
                rsa.algorithm = .rsassa_pss(hash: hashAlgorithm, saltLength: saltLength)
            default:
                fatalError("Unimplemented RSA algorithm \(rsa.algorithm)")
            }
            
            return rsa
        default:
            fatalError("Unsupported certificate \(_signing)")
        }
    }
        
    private var _signing: Signing
    
    public init?(certificateFile: String, privateKeyFile: String)
    {
        if let rsa = RSA.fromPEMFile(privateKeyFile) {
            _signing = rsa
        }
        else {
            return nil
        }
        
        certificateChain = []
        for (section, object) in ASN1Parser.sectionsFromPEMFile(certificateFile) {
            switch section {
            case "CERTIFICATE":
                if let certificate = X509.Certificate(derData: object.underlyingData!) {
                    certificateChain.append(certificate)
                }
            default:
                break
            }
        }
        
        if certificateChain.count == 0 {
            return nil
        }
    }
    
    public convenience init?(pemFile: String)
    {
        self.init(certificateFile: pemFile, privateKeyFile: pemFile)
    }
}

public protocol Identity
{
    var certificateChain: [X509.Certificate] { get }
    func signer(with hashAlgorithm: HashAlgorithm) -> Signing
}

extension PEMFileIdentity : Identity {}
