//
//  TLSRecord1_3.swift
//  
//
//  Created by Rake Yang on 2021/9/13.
//

import Foundation

class TLSRecord1_3: TLSRecordProtocol {
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
        case .handshake(let handshakeType):
            if let msg = context.nextMessage {
                context.sendMessage(msg: msg)
            } else {
                if let handshakeMsg = msg as? TLSHandshakeMessage {
                    context.handshakeMessages.append(handshakeMsg)
                    switch handshakeType {
                    case .finished:
                        handshaked = true
                        TLSSessionManager.shared.delegate?.didHandshakeFinished(context)
                    default:break
                    }
                }
            }
        case .alert:
            var alert: TLSAlert?
            if cipherChanged {
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
            if let decryptedData = try s.decrypt(appData.encryptedData, contentType: msg.type) {
                if handshaked {
                    TLSSessionManager.shared.delegate?.didReadApplication(decryptedData, connection: context, tag: context.readWriteTag)
                } else {
                    if let newMsg = TLSMessage.fromData(data: decryptedData, context: context) {
                        try didReadMessage(newMsg, rawData: decryptedData)
                    }
                }
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
            if let msg = context.nextMessage {
                if let encrypted = s.encrypt(msg.dataWithBytes(), contentType: msg.type) {
                    context.sendMessage(msg: TLSApplicationData(encrypted, context: context))
                }
            }
        case .handshake(let handshakeType):
            if let msg = context.nextMessage {
                context.sendMessage(msg: msg)
            } else {
                switch handshakeType {
                case .finished:
                    return .changeCipherSpec
                default:
                    break
                }
            }
            break
        case .applicationData:
            if handshaked {
                TLSSessionManager.shared.delegate?.didWriteApplication(context, tag: context.readWriteTag)
            } else {
                _ = sendNext()
            }
        default:
            break
        }
        return nil
    }
}
