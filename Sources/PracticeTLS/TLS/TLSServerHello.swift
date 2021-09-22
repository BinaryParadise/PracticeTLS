//
//  TLSServerHello.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

public class TLSServerHello: TLSHandshakeMessage {
    var random: Random = Random()
    var sessionID: [UInt8] = []
    /// 必须选择客户端支持的加密套件，此处仅实现一两种
    var cipherSuite: CipherSuite
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = [] //[.init(type: .renegotiation_info, length: 1, ext: [0])]
    var extensionLength: UInt16 {
        return UInt16(extensions.reduce(0, { r, ext in
            r + ext.dataWithBytes().count
        }))
    }
    var hmac = HashAlgorithm.sha256.macAlgorithm.hmacFunction
    
    var client: TLSClientHello?

    init(client: TLSClientHello, context: TLSConnection) {
        self.client = client
        
        //启用: h2
        #if false
        context.isHTTP2Enabled = true
        extensions = [.init(type: .application_layer_protocol_negotiation, length: 5, ext: [0x00, 0x03, 0x02, 0x68, 0x32])]
        extLen = 9
        #endif
        
        //确定版本、加密套件
        if (client.extend(.supported_versions) as? TLSSupportedVersionsExtension)?.versions.contains(.V1_3) ?? false {
            sessionID = client.sessionID ?? []
            cipherSuite = .TLS_AES_128_GCM_SHA256
            context.negotiatedProtocolVersion = .V1_3
            context.record = TLS1_3.RecordLayer(context)
            context.preMasterKey = client.keyExchange
        } else {
            let expectedCipher: CipherSuite = .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            if client.cipherSuites.contains(expectedCipher) {
                cipherSuite = expectedCipher
            } else {
                cipherSuite = .TLS_RSA_WITH_AES_128_GCM_SHA256
            }
            context.record = TLS1_2.RecordLayer(context)
        }
                        
        //踩坑：这里要完整32字节⚠️⚠️⚠️⚠️⚠️
        context.record.s.clientRandom = client.random.dataWithBytes()
        context.record.s.serverRandom = random.dataWithBytes()
        context.record.setPendingSecurityParametersForCipherSuite(cipherSuite)
        context.cipherSuite = cipherSuite
        
        super.init(.serverHello)
        
        switch context.keyExchange {
        case .rsa:
            let cert = TLSCertificate()
            cert.nextMessage = TLSServerHelloDone()
            nextMessage = cert
        case .ecdha(let encryptor):
            serverKeyExchange(encryptor.exportPublickKey(), context: context)
        }
    }
    
    private func serverKeyExchange(_ pubKey: [UInt8], context: TLSConnection) {
        if context.negotiatedProtocolVersion == .V1_3 {
            extensions.append(TLSSupportedVersionsExtension(context.negotiatedProtocolVersion))
            extensions.append(TLSKeyShareExtension(keyShare: .serverHello(KeyShareEntry(group: selectedCurve, keyExchange:pubKey))))
        } else {
            let cert = TLSCertificate()
            cert.nextMessage = try? TLSServerKeyExchange(cipherSuite, pubKey: pubKey, serverHello: self)
            nextMessage = cert
        }
    }
    
    func extend(_ type: TLSExtensionType) -> TLSExtension? {
        return extensions.first { ext in
            ext.type == type
        }
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes:[UInt8] = []
        bytes.write(version.rawValue.bytes)
        bytes.write(random.dataWithBytes()) //32 bytes
        bytes.write(UInt8(truncatingIfNeeded: sessionID.count)) //1 byte
        bytes.write(sessionID) //0 or 32 bytes
        bytes.write(cipherSuite.rawValue.bytes) //2 bytes
        bytes.write(compressionMethod.rawValue) //1 byte
        if extensions.count > 0 {
            bytes.write(extensionLength.bytes) //2 bytes
            bytes.write(extensions.reduce([], { r, ext in
                r + ext.dataWithBytes()
            }))
        }
        writeHeader(data: &bytes)
        return bytes
    }
}

public func TLSFillWithRandomBytes(_ buffer: UnsafeMutableRawBufferPointer)
{
    #if os(Linux)
    struct SeedSetter {
        static let fd: Int32? = {
            let fd = open("/dev/urandom", O_RDONLY)
            guard fd >= 0 else {
                return nil
            }
            var seed: UInt32 = 0
            let seedSize = MemoryLayout<UInt32>.size
            let result = read(fd, &seed, seedSize)
            guard result == seedSize else {
                return nil
            }
            close(fd)
            
            srandom(seed)
            
            return fd
        }()
    }
    
    _ = SeedSetter.fd
    
    let uint8buffer = buffer.bindMemory(to: UInt8.self)
    for i in 0..<buffer.count {
        uint8buffer[i] = UInt8(random() & 0xff)
    }
    #else
    arc4random_buf(buffer.baseAddress, buffer.count)
    #endif
}

public func TLSRandomBytes(count: Int) -> [UInt8]
{
    var randomBytes = [UInt8](repeating: 0, count: count)
    
    randomBytes.withUnsafeMutableBytes { (buffer)  in
        TLSFillWithRandomBytes(buffer)
    }
    
    return randomBytes
}
