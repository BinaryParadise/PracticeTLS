//
//  TLSServerHello.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

public class TLSServerHello: TLSHandshakeMessage {
    var bodyLength: Int = 0
    var clientVersion: TLSVersion = .V1_2
    var random: Random = Random()
    var sessionID: String?
    /// 必须选择客户端支持的加密套件，此处仅实现一种
    var cipherSuite: CipherSuite
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = [] //[.init(type: .renegotiation_info, length: 1, ext: [0])]
    let extLen: UInt16 = 0

    override init() {
        cipherSuite = .TLS_RSA_WITH_AES_256_CBC_SHA256
        super.init()
        type = .handeshake
        handshakeType = .serverHello
        version = .V1_2
        contentLength = 42 + (extLen > 0 ? 2 : 0) + extLen
        bodyLength = Int(contentLength - 4)
    }
    
    required init?(stream: DataStream) {
        fatalError("init(stream:) has not been implemented")
    }
    
    public override func responseMessage() -> TLSHandshakeMessage? {
        let cert = TLSCertificate()
        cert.version = version
        return cert
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes:[UInt8] = []
        //header
        bytes.append(type.rawValue) // 1 byte
        bytes.append(contentsOf: version.rawValue.bytes) // 2 bytes
        bytes.append(contentsOf: UInt16(contentLength).bytes) // 2 bytes
        
        //body
        bytes.append(handshakeType.rawValue) // 1 byte
        bytes.append(contentsOf: UInt(bodyLength).bytes[1..<4]) //3 bytes
        bytes.append(contentsOf: clientVersion.rawValue.bytes) //2 bytes
        bytes.append(contentsOf: random.dataWithBytes()) //32 bytes
        bytes.append(UInt8(truncatingIfNeeded: sessionID?.count ?? 0)) //1 byte
        bytes.append(contentsOf: cipherSuite.rawValue.bytes) //2 bytes
        bytes.append(compressionMethod.rawValue) //1 byte
        if extensions.count > 0 {
            bytes.append(contentsOf: extLen.bytes) //2 bytes
            extensions.forEach { ext in
                bytes.append(contentsOf: ext.bytes)
            }
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
