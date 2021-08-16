//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/13.
//

import Foundation
import CocoaAsyncSocket

let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
let TLSServerFinishedLabel = [UInt8]("server finished".utf8)
let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

class TLSConnection: NSObject {
    var sock: GCDAsyncSocket
    var nextMessage: TLSHandshakeMessage?
    var clientRandom: [UInt8] = []
    var serverRandom: [UInt8] = []
    var preMasterKey: [UInt8] = []
    var masterSecret: [UInt8] = []
    var handshakeMessages: [TLSHandshakeMessage] = []
    var version: TLSVersion = .V1_2
    
    init(_ sock: GCDAsyncSocket) {
        self.sock = sock
        super.init()
        sock.delegate = self
    }
    
    func handshake() {
        sock.readData(tag: .handshake(.clientHello))
    }
    
    private func calculateMasterSecret() -> [UInt8]
    {
        return PRF(secret: preMasterKey, label: [UInt8]("master secret".utf8), seed: clientRandom + serverRandom, outputLength: 48)
    }
    
    func verifyDataForFinishedMessage(isClient: Bool = false) -> [UInt8] {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        var handshakeData: [UInt8] = []
        for msg in handshakeMessages {
            handshakeData.append(contentsOf: msg.dataWithBytes().bytes)
        }
        let transcriptHash = HashAlgorithm.sha256.hashFunction([UInt8](handshakeData.dropLast(0)))
        return PRF(secret: masterSecret, label: finishedLabel, seed: transcriptHash, outputLength: 12)
    }
    
    func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8] {
        return P_hash(HMAC_SHA256, secret: secret, seed: label + seed, outputLength: outputLength)
    }
}

extension TLSConnection: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        let handshakeType = TLSHandshakeType(rawValue: UInt8(tag)) ?? .clientHello
        LogDebug("\(handshakeType)")
        let stream = DataStream(data)
        if let byte = stream.readByte(), let type = TLSMessageType(rawValue: byte) {
            switch type {
            case .changeCipherSpec:
                break
            case .alert:
                LogError("alert")
                sock.disconnectAfterReadingAndWriting()
                break
            case .handeshake:
                if let msg = TLSHandshakeMessage.fromData(data: data) {
                    switch msg {
                    case is TLSClientHello:
                        let clientHello = msg as! TLSClientHello
                        clientRandom = clientHello.random.randomBytes
                        tlsResponse(msg.responseMessage())
                    case is TLSClientKeyExchange:
                        let exchange = msg as! TLSClientKeyExchange
                        preMasterKey = exchange.preMasterSecret.preMasterKey
                        masterSecret = calculateMasterSecret()
                        tlsResponse(msg.responseMessage())
                    default: break
                    }
                }
            case .applicatonData:
                break
            }
        } else {
            LogError("不符合TLS报文协议")
        }
    }
    
    func finishedMessage() -> TLSHandshakeMessage {
        let encryptedMessage = TLSEncryptedMessage()
        encryptedMessage.version = version
        let aes = AES(key: masterSecret, bitSize: .aes256, encrypt: true)
        let cipher = BlockCipher.init(encrypt: true, cryptor: aes, mode: .cbc, cipher: .aes256)
        
        let hmacSize = MACAlgorithm.hmac_sha1.size
        let numberOfKeyMaterialBytes = 2 * (hmacSize + CipherAlgorithm.aes256.keySize + 16)
        let keyBlock = PRF(secret: masterSecret, label: TLSKeyExpansionLabel, seed: serverRandom + clientRandom, outputLength: numberOfKeyMaterialBytes)
        
        let encodeKeySize = CipherAlgorithm.aes256.keySize
        
        var index = 0
        let clientWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
        index += hmacSize
        
        let serverWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
        index += hmacSize
        
        let clientWriteKey = [UInt8](keyBlock[index..<index + encodeKeySize])
        index += encodeKeySize
        
        let serverWriteKey = [UInt8](keyBlock[index..<index + encodeKeySize])
        index += encodeKeySize
        
        let blockLength = CipherAlgorithm.aes256.blockSize
        let clientWriteIV = [UInt8](keyBlock[index..<index + CipherAlgorithm.aes256.blockSize])
        index += blockLength
        
        let serverWriteIV = [UInt8](keyBlock[index..<index + CipherAlgorithm.aes256.blockSize])
        index += blockLength
        
        let verifyData = verifyDataForFinishedMessage()
        let mac = self.calculateMessageMAC(secret: masterSecret, contentType: .handeshake, data: verifyData, isRead: false) ?? []
        var plainTextRecordData = verifyData + mac

        let recordIV = TLSRandomBytes(count: 16)
        let paddingLength = blockLength - ((plainTextRecordData.count) % blockLength)
        if paddingLength != 0 {
            let padding = [UInt8](repeating: UInt8(paddingLength - 1), count: paddingLength)
            
            plainTextRecordData.append(contentsOf: padding)
        }
        encryptedMessage.message = cipher?.update(data: plainTextRecordData, authData: [], key: serverWriteKey, IV: recordIV) ?? []
        return encryptedMessage
    }
    
    private func calculateMessageMAC(secret: [UInt8], contentType : TLSMessageType, data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        guard let MACHeader = self.MACHeader(forContentType: contentType, dataLength: data.count, isRead: isRead) else { return nil }
        
        return self.calculateMAC(secret: secret, data: MACHeader + data, isRead: isRead)
    }
    
    private func MACHeader(forContentType contentType: TLSMessageType, dataLength: Int, isRead: Bool) -> [UInt8]? {
        var macData: [UInt8] = []
        macData.append(0)
        macData.append(contentType.rawValue)
        macData.append(contentsOf: version.rawValue.bytes())
        macData.append(contentsOf: UInt16(dataLength).bytes())
        
        return macData
    }
    
    private func calculateMAC(secret : [UInt8], data : [UInt8], isRead : Bool) -> [UInt8]? {
        return MACAlgorithm.hmac_sha1.hmacFunction(secret, data)
    }
    
    func tlsResponse(_ msg: TLSHandshakeMessage?) -> Void {
        if let msg = msg {
            if msg is TLSServerHello {
                let serverHello = msg as! TLSServerHello
                serverRandom = serverHello.random.randomBytes
            }
            handshakeMessages.append(msg)
            if msg is TLSChangeCipherSpec {
                let changeCipher = msg as! TLSChangeCipherSpec
                if !changeCipher.isClient {
                    nextMessage = finishedMessage()
                }
                sock.writeData(data: msg.dataWithBytes(), tag: .handshake(.finished))
            } else {
                nextMessage = msg.responseMessage()
                sock.writeData(data: msg.dataWithBytes(), tag: .handshake(msg.handshakeType))
            }
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        let handshakeType = TLSHandshakeType(rawValue: UInt8(tag)) ?? .clientHello
        LogDebug("\(handshakeType)")
        if let msg = nextMessage {
            tlsResponse(msg)
        } else {
            if handshakeType == .serverHelloDone {
                sock.readData(tag: .handshake(.clientKeyExchange))
            } else {
                sock.readData(tag: .handshake(handshakeType))
            }
        }
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        if let err = err {
            LogError("\(err)")
        }
        TLSSessionManager.shared.sessions.removeValue(forKey: sock.socket4FD())
    }
}
