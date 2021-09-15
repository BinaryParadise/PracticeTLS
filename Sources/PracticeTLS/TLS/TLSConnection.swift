//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/13.
//

import Foundation
import CocoaAsyncSocket
import CryptoSwift
import SecurityRSA

public let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
public let TLSServerFinishedLabel = [UInt8]("server finished".utf8)
public let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

public class TLSConnection: NSObject {
    var sessionId: String
    public var sock: GCDAsyncSocket
    var nextMessage: TLSMessage?
    var preMasterKey: [UInt8] = []
    var handshakeMessages: [TLSMessage] = []
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
    
    var transcriptHash: [UInt8] {
        var handshakeData: [UInt8] = []
        for msg in handshakeMessages {
            let d = msg.messageData()
            //print("//\(msg.type) => \(d.count) \(d.toHexString())")
            handshakeData.append(contentsOf: d)
            // TODO: Check for special construct when a HelloRetryRequest is included
            // see section 4.4.1 "The Transcript Hash" in RFC 8446
        }
        return record.s.hashAlgorithm.hashFunction(handshakeData.dropLast(0))
    }
    
    init(_ sock: GCDAsyncSocket) {
        self.sock = sock
        sessionId = AES.randomIV(16).toHexString()
        super.init()
        self.sock.delegate = self
    }
    
    func handshake() {
        LogInfo("handshake start")
        sock.readData(tag: .handshake(.clientHello))
    }
    
    func verifyDataForFinishedMessage(isClient: Bool) -> TLSFinished {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        let verifyData = record.s.PRF(secret: record.s.masterSecret, label: finishedLabel, seed: transcriptHash, outputLength: 12)
        return TLSFinished(verifyData)
    }
    
    public func disconnect() {
        sock.disconnectAfterWriting()
    }
    
    public func readApplication(tag: Int) {
        readWriteTag = tag
        if lastPacket {
            //处理粘包，若为最后一个包开始新读取
            sock.readData(tag: .applicationData)
        }
    }
    
    public func writeApplication(data: [UInt8], tag: Int) {
        readWriteTag = tag
        sendData(TLSApplicationData(data, context: self).dataWithBytes(), tag: .applicationData)
    }
    
    func decryptAndVerifyMAC(contentType : TLSMessageType, data : [UInt8]) throws -> [UInt8]? {
        return try record.decrypt(data, contentType: contentType)
    }
        
    func sendMessage(msg: TLSMessage?) {
        guard let msg = msg else { return }
        let data: [UInt8] = record.cipherChanged ? TLSApplicationData(msg, context: self).dataWithBytes() : msg.dataWithBytes()
        nextMessage = msg.nextMessage
        if msg is TLSHandshakeMessage {
            handshakeMessages.append(msg)
        }
        sendData(data, tag: msg.rwtag)
    }
    
    func sendData(_ sendData: [UInt8], tag: RWTags) {
        if maximumRecordSize < sendData.count {
            let page = (sendData.count/maximumRecordSize+(sendData.count%maximumRecordSize > 0 ? 1:0))
            for i in 0..<page {
                let cur = sendData[i*maximumRecordSize..<min(sendData.count, (i+1)*maximumRecordSize)]
                sock.writeData(data: Array(cur), tag: i < page-1 ? .fragment : tag)
            }
        } else {
            sock.writeData(data: sendData, tag: tag)
        }
    }
}

extension TLSConnection: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
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
                    try record.didReadMessage(msg, rawData: rawData)
                } catch {
                    LogError("\(error)")
                }
            } else {
                LogDebug("未识别 -> \(rawData.count)")
            }
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        let wtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(wtag)")
        if let nextRead = record.didWriteMessage(wtag) {
            sock.readData(tag: nextRead)
        }
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        LogInfo("\(err)")
        TLSSessionManager.shared.clearConnection(self)
    }
}
