//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/11.
//

import Foundation

enum ECCurveType {
    case namedCurve(NamedGroup)
    var numericECCurveType : UInt8 {
        switch self {
        case .namedCurve(_): return 3
        }
    }
}

struct ECDiffieHellmanParameters: Streamable {
    var curveType : ECCurveType
    
    var publicKey : EllipticCurvePoint!
    
    var curve : EllipticCurve {
        get {
            switch self.curveType
            {
            case .namedCurve(let namedCurve):
                guard let curve = EllipticCurve.named(namedCurve) else {
                    fatalError("Unsuppored curve \(namedCurve)")
                }
                return curve
                
            default:
                fatalError("Unsupported curve type \(self.curveType)")
            }
        }
    }
    
    init() {
        curveType = .namedCurve(.secp256r1)
        let ecdhKeyExchange = ECDHKeyExchange(curve: curve)
        let Q = ecdhKeyExchange.calculatePublicKeyPoint()
        publicKey = Q
    }
    
    func dataWithBytes() -> Data {
        var data = Data()
        data.append(curveType.numericECCurveType)
        data.append(contentsOf: curve.name.rawValue.bytes())
        data.append(UInt8(publicKey.dataWithBytes().count))
        data.append(contentsOf: publicKey.dataWithBytes())
        return data
    }
}

class TLSServerKeyExchange: TLSHandshakeMessage {
    var parameters:  ECDiffieHellmanParameters
    var signedParameters: TLSSignedData
    override init() {
        parameters = ECDiffieHellmanParameters()
        signedParameters = TLSSignedData(data: parameters.dataWithBytes())
        super.init()
        contentLength = UInt16(4 + parameters.dataWithBytes().count + signedParameters.dataWithBytes().count)
        handshakeType = .serverKeyExchange
    }
    
    required init?(stream: DataStream) {
        fatalError("init(stream:) has not been implemented")
    }
    
    override func dataWithBytes() -> Data {
        var data = Data()
        
        data.append(type.rawValue)
        data.append(contentsOf: version.rawValue.bytes())
        data.append(contentsOf: contentLength.bytes())
        
        data.append(handshakeType.rawValue)
        
        //ECDHE
//        data.append(contentsOf: UInt(contentLength-4).bytes()[1...3])
//        data.append(contentsOf: parameters.dataWithBytes())
//        data.append(contentsOf: signedParameters.dataWithBytes())
        
        //RSA
        return data
    }
}
