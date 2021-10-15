//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/13.
//

import Foundation
import Socket
import CryptoSwift

public let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
public let TLSServerFinishedLabel = [UInt8]("server finished".utf8)
public let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

protocol TLSSocketStream {
    func readData(_ tag: RWTags) -> [UInt8]
    
    func writeData(_ data: [UInt8]?, tag: RWTags)
    
    func disconnect()
}

public class TLSConnection {
    var sessionId: String
    var sock: TLSSocketStream
    var nextMessage: TLSMessage?
    var preMasterKey: [UInt8] = []
    var handshakeMessages: [TLSHandshakeMessage] = []
    public var version: TLSVersion = .V1_2
    public var cipherSuite: CipherSuite = .TLS_RSA_WITH_AES_128_GCM_SHA256
    var maximumRecordSize: Int = 2048
    private var http2Enabled = false
    public var isHTTP2Enabled: Bool {
        return http2Enabled
    }
    public var readWriteTag: Int = 0
    
    /// 最后一个包（粘包处理）
    public var lastPacket: Bool = true
    public var handshaked: Bool = false
    var keyExchange: TLSKeyExchange = .rsa
    private var _record: TLSRecordProtocol?
    var record: TLSRecordProtocol!
    public var negotiatedProtocolVersion: TLSVersion = .V1_2
    var socketQueue: DispatchQueue = DispatchQueue(label: "SocketQueue", attributes: .init(rawValue: 0))
    
    public var connectedHost: String {
        return (sock as? Socket)?.remoteHostname ?? "known"
    }
    
    var transcriptHash: [UInt8] {
        var handshakeData: [UInt8] = []
        for msg in handshakeMessages {
            
            if negotiatedProtocolVersion == .V1_3 {
                // TODO: Check for special construct when a HelloRetryRequest is included
                // see section 4.4.1 "The Transcript Hash" in RFC 8446
                // 踩坑: ⚠️⚠️⚠️
                if msg is TLSHelloRetryRequest {
                    let hashLength = record.s.hashAlgorithm.hashLength
                    let hashValue = record.s.hashAlgorithm.hashFunction(handshakeData)
                    
                    handshakeData = [TLSHandshakeType.messageHash.rawValue, 0, 0, UInt8(hashLength)] + hashValue
                    //LogWarn("hashed => \(handshakeData.count)")
                }
            }
            
            handshakeData.append(contentsOf: msg.dataWithBytes())
        }
//        LogWarn(handshakeMessages.map { msg in
//            "\(msg)_\(msg.dataWithBytes().count)"
//        }.joined(separator: ", "))
        return record.s.hashAlgorithm.hashFunction(handshakeData)
    }
    
    init(_ sock: TLSSocketStream) {
        self.sock = sock
        sessionId = AES.randomIV(16).toHexString()
    }
    
    func handshake() {
        LogInfo("handshake start")
        asyncRead(tag: .handshake(.clientHello))
    }
    
    func verifyDataForFinishedMessage(isClient: Bool) -> [UInt8] {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        let verifyData = record.s.PRF(secret: record.s.masterSecret, label: finishedLabel, seed: transcriptHash, outputLength: 12)
        return verifyData
    }
    
    public func disconnect() {
        sock.disconnect()
        TLSSessionManager.shared.clearConnection(self)
    }
    
    public func readApplication(tag: Int) {
        readWriteTag = tag
        if lastPacket {
            //处理粘包，若为最后一个包开始新读取
            asyncRead(tag: .applicationData)
        }
    }
    
    public func writeApplication(data: [UInt8], tag: Int) {
        readWriteTag = tag
        sendMessage(msg: TLSApplicationData(plantData: data))
    }
    
    func decryptAndVerifyMAC(contentType : ContentType, data : [UInt8]) throws -> [UInt8]? {
        return try record.decrypt(data, contentType: contentType)
    }
        
    func sendMessage(msg: TLSMessage?) {
        guard let msg = msg else { return }
        var prepareData: [UInt8] = []
        if record.serverCipherChanged {
            if negotiatedProtocolVersion == .V1_3 {
                prepareData.write(ContentType.applicationData.rawValue)
            } else {
                prepareData.write(msg.contentType.rawValue)
            }
        } else {
            prepareData.write(msg.contentType.rawValue)
        }
        prepareData.write(version.rawValue.bytes)
        let contentData = record.serverCipherChanged ? TLSApplicationData(msg, context: self).dataWithBytes() : msg.dataWithBytes()
        prepareData.write(UInt16(contentData.count).bytes)
        
        prepareData.write(contentData)
        
        nextMessage = msg.nextMessage
        if let handshake =  msg as? TLSHandshakeMessage {
            handshakeMessages.append(handshake)
        }
        
        asyncWrite(data: prepareData, tag: msg.rwtag)
    }
    
    func asyncRead(tag: RWTags) {
        socketQueue.async { [weak self] in
            guard let self = self else { return }
            self.socket(didRead: self.sock.readData(tag), withTag: tag)
        }
    }
    
    func asyncWrite(data: [UInt8]?, tag: RWTags) -> Void {
        socketQueue.async { [weak self] in
            guard let self = self else { return }
            self.sock.writeData(data, tag: tag)
            self.socket(didWriteDataWithTag: tag)
        }
    }
}

extension TLSConnection {
    func socket(didRead data: [UInt8], withTag tag: RWTags) {
        //处理粘包
        let stream = DataStream(data)
        while !stream.endOfStream {
            stream.read(count: 3)
            let length = stream.readUInt16() ?? 0
            stream.position -= 5
            let rawData = stream.read(count: UInt16(5 + length)) ?? []
            if let msg = TLSMessage.fromData(data: rawData, context: self) {
                if stream.endOfStream {
                    lastPacket = true
                }
                do {                    
                    if let handshake =  msg as? TLSHandshakeMessage {
                        if !record.clientCipherChanged {
                            handshakeMessages.append(handshake)
                        }
                    }
                    try record.didReadMessage(msg, rawData: rawData, unpack: false)
                } catch {
                    LogError("\(error)")
                }
            } else {
                LogDebug("未识别 -> \(rawData.count)")
            }
        }
    }
    
    func socket(didWriteDataWithTag tag: RWTags) {
        LogInfo("\(tag)")
        if let nextRead = record.didWriteMessage(tag) {
            asyncRead(tag: nextRead)
        }
    }
}
