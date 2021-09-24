//
//  TLSClientHello.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

public class TLSClientHello: TLSHandshakeMessage {
    var random: Random = Random()
    var sessionID: [UInt8]?
    var cipherSuites: [CipherSuite] = []
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = []
    var keyExchange: [UInt8] {
        return (extend(.key_share) as? TLSKeyShareExtension)?.entry(nameGroup: selectedCurve)?.keyExchange ?? []
    }

    public override init?(stream: DataStream, context: TLSConnection) {
        super.init(stream: stream, context: context)
        stream.readUInt16()
        random = Random(stream: (stream.read(count: 32) ?? []).stream)
        if let len = stream.readByte(), len > 0 {
            sessionID = stream.read(count: Int(len))
        }
        if let cipherLen = stream.readUInt16() {
            if let bytes = stream.read(count: Int(cipherLen)) {
                let cipherS = DataStream(Data(bytes))
                while true {
                    if let item = cipherS.readUInt16() {
                        if let suite = CipherSuite(rawValue: item) {
                            cipherSuites.append(suite)
                        } else {
                            //print("\(String(format: "unsupport cipher suite: 0x%0X", item))")
                        }
                    } else {
                        break
                    }
                }
            }
        }
        if let len = stream.readByte(), let method = stream.read(count: Int(len))?.first {
            compressionMethod = CompressionMethod(rawValue: method) ?? .null
        }
        if let extLen = stream.readUInt16(), let bytes = stream.read(count: Int(extLen)) {
            extensions = TLSExtensionsfromData(bytes, messageType: .clientHello)
        }
        
        if (extend(.supported_versions) as? TLSSupportedVersionsExtension)?.versions.contains(.V1_3) ?? false {
            if keyExchange.count == 0 {
                nextMessage = TLSHelloRetryRequest(client: self, context: context)                
            } else {                
                nextMessage = TLSServerHello(client: self, context: context)
            }
        } else {            
            nextMessage = TLSServerHello(client: self, context: context)
        }
        context.nextMessage = nextMessage
    }
    
    func extend(_ type: TLSExtensionType) -> TLSExtension? {
        return extensions.first { ext in
            ext.type == type
        }
    }
}
