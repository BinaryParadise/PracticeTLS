//
//  TLSRecord1_2.swift
//  
//
//  Created by Rake Yang on 2021/9/13.
//

import Foundation

class TLSRecord1_2: TLSRecordProtocol {
    var context: TLSConnection
    var handshaked: Bool = false
    var cipherChanged: Bool = false
    var s: TLSSecurityParameters {
        return context.securityParameters
    }
    
    required init(_ context: TLSConnection) {
        self.context = context
    }
    
    func didReadMessage(_ msg: TLSMessage, rawData: [UInt8]) throws {
        LogDebug("\(msg.type) -> \(rawData.count)")
        switch msg.type {
        case .changeCipherSpec:
            cipherChanged = true
        case .handshake(_):
            if let handshake = msg as? TLSHandshakeMessage {
                switch handshake.handshakeType {
                case .finished:
                    s.clientVerifyData = context.verifyDataForFinishedMessage(isClient: true).dataWithBytes()
                    s.clientVerifyData = try context.decryptAndVerifyMAC(contentType: handshake.type, data: handshake.messageData()) ?? []
                    context.sock.writeData(data: TLSChangeCipherSpec().dataWithBytes(), tag: .changeCipherSpec)
                default:
                    context.handshakeMessages.append(handshake)
                    context.sendMessage(msg: handshake.nextMessage)
                }
            }
        case .alert:
            var alert: TLSAlert?
            if handshaked {
                if let d = try s.decrypt([UInt8](rawData[5...]), contentType: .alert) {
                    alert = TLSAlert(stream: ([UInt8](rawData[0...4]) + d).stream, context: context)
                }
            } else {
                alert = TLSAlert(stream: rawData.stream, context: context)
            }
            if let alert = alert {
                if alert.alertType == .closeNotify {
                    context.sock.disconnectAfterReadingAndWriting()
                }
                LogError("alert: \(alert.level) -> \(alert.alertType)")
            } else {
                LogError("alert未识别 -> \(rawData.count)")
            }
        case .applicationData:
            let appData = msg as! TLSApplicationData
            if let httpData = try s.decrypt(appData.encryptedData, contentType: msg.type) {
                TLSSessionManager.shared.delegate?.didReadApplication(httpData, connection: context, tag: context.readWriteTag)
            }
        }
    }
    
    func didWriteMessage(_ tag: RWTags) -> RWTags? {
        let sendNext:() -> Bool = { [weak self] in
            if let msg = self?.context.nextMessage {
                self?.context.sendMessage(msg: msg)
                return true
            }
            return false
        }
        
        switch tag {
        case .changeCipherSpec:
            let clientFinishedMsg = context.verifyDataForFinishedMessage(isClient: true)
            //踩坑：发送给客户端的finish也需要包含在摘要的握手消息中⚠️⚠️⚠️⚠️⚠️
            context.handshakeMessages.append(clientFinishedMsg)
            
            s.serverVerifyData = context.verifyDataForFinishedMessage(isClient: false).dataWithBytes()
            if let encrypted = s.encrypt(s.serverVerifyData, contentType: .handshake(.finished)) {
                let finishedMsg = TLSHandshakeMessage(.finished)
                finishedMsg.encrypted = encrypted
                context.sock.writeData(data: finishedMsg.dataWithBytes(), tag: .handshake(.finished))
            }
        case .handshake(let handshakeType):
            if sendNext() {
                
            } else {
                switch handshakeType {
                case .serverHelloDone:
                    return .handshake(.clientKeyExchange)
                case .finished:
                    handshaked = true
                    TLSSessionManager.shared.delegate?.didHandshakeFinished(context)
                default:
                    break
                }
            }
            break
        case .applicationData:
            if handshaked {
                TLSSessionManager.shared.delegate?.didWriteApplication(context, tag: context.readWriteTag)
            }
        default:
            break
        }
        return nil
    }
}
