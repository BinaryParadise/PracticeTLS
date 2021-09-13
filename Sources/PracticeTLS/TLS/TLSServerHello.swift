//
//  TLSServerHello.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

public class TLSServerHello: TLSHandshakeMessage {
    var bodyLength: Int = 0
    var random: Random = Random()
    var sessionID: [UInt8] = []
    /// 必须选择客户端支持的加密套件，此处仅实现一两种
    var cipherSuite: CipherSuite = .TLS_RSA_WITH_AES_128_GCM_SHA256
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = [] //[.init(type: .renegotiation_info, length: 1, ext: [0])]
    var extensionLength: UInt16 {
        return UInt16(extensions.reduce(0, { r, ext in
            r + ext.dataWithBytes().count
        }))
    }
    var hmac = HashAlgorithm.sha256.macAlgorithm.hmacFunction
    
    var supportVersion: TLSVersion?
    var client: TLSClientHello?

    init(client: TLSClientHello, context: TLSConnection) {
        super.init(.serverHello)
        self.client = client
            
        sessionID = client.sessionID ?? []
        
        contentLength = 42 + (extensionLength > 0 ? 2 : 0) + extensionLength
        bodyLength = Int(contentLength - 4)
        
        //启用: h2
        #if false
        context.isHTTP2Enabled = true
        extensions = [.init(type: .application_layer_protocol_negotiation, length: 5, ext: [0x00, 0x03, 0x02, 0x68, 0x32])]
        extLen = 9
        #endif
        
        //选定TLS版本
        if let suppertedVersions = client.extensions.first(where: { ext in
            ext is TLSSupportedVersionsExtension
        }) as? TLSSupportedVersionsExtension {
            if suppertedVersions.versions.contains(.V1_3) {
                supportVersion = .V1_3
                context.record = TLSRecord1_3(context)
            }
        }
        
        //选定加密套件
        if supportVersion == .V1_3 {
            cipherSuite = .TLS_AES_128_GCM_SHA256
        } else {
            let expectedCipher: CipherSuite = .TLS_RSA_WITH_AES_256_CBC_SHA256
            if client.cipherSuites.contains(expectedCipher) {
                cipherSuite = expectedCipher
            }
        }
        
        context.setPendingSecurityParametersForCipherSuite(cipherSuite)
        context.securityParameters.serverRandom = random.dataWithBytes()
        
        version = context.version
                
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
        
        if supportVersion == .V1_3 {
            extensions.append(TLSSupportedVersionsExtension())
            extensions.append(TLSKeyShareExtension(keyShare: .serverHello(KeyShareEntry(group: .x25519, keyExchange:pubKey))))
            
            context.securityParameters.keyExchange(algorithm: .ecdhe, preMasterSecret: pubKey)
            let spec = TLSChangeCipherSpec()
            spec.nextMessage = TLSEncryptedExtensions(context: context)
            nextMessage = spec
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
                
        contentLength = 42 + (extensionLength > 0 ? 2 : 0) + extensionLength + UInt16(sessionID.count)
        bodyLength = Int(contentLength - 4)
        
        //header
        bytes.append(type.rawValue) // 1 byte
        bytes.append(contentsOf: version.rawValue.bytes) // 2 bytes
        bytes.append(contentsOf: UInt16(contentLength).bytes) // 2 bytes
        
        //body
        bytes.append(handshakeType.rawValue) // 1 byte
        bytes.append(contentsOf: UInt(bodyLength).bytes[1..<4]) //3 bytes
        bytes.append(contentsOf: version.rawValue.bytes) //2 bytes
        bytes.append(contentsOf: random.dataWithBytes()) //32 bytes
        bytes.append(UInt8(truncatingIfNeeded: sessionID.count)) //1 byte
        bytes.append(contentsOf: sessionID) //0 or 32 bytes
        bytes.append(contentsOf: cipherSuite.rawValue.bytes) //2 bytes
        bytes.append(compressionMethod.rawValue) //1 byte
        if extensions.count > 0 {
            bytes.append(contentsOf: extensionLength.bytes) //2 bytes
            bytes.append(contentsOf: extensions.reduce([], { r, ext in
                r + ext.dataWithBytes()
            }))
        }
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
