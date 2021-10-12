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
    public var publicPEM: String
    public var privatePEM: String
    
    public init?(certificateFile: String, privateKeyFile: String)
    {
        publicPEM = certificateFile
        privatePEM = privateKeyFile
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
    func signer(with hashAlgorithm: HashAlgorithm) -> Signing?
}

extension PEMFileIdentity: Identity {
    public func signer(with hashAlgorithm: HashAlgorithm) -> Signing? {
        return nil
    }
    
    
}
