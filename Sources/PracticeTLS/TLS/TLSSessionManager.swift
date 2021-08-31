//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation
import CocoaAsyncSocket

public protocol TLSConnectionDelegate {
    /// TLS握手完成
    func didHandshakeFinished(_ connection: TLSConnection)
    func didWriteApplication(_ connection: TLSConnection, tag: Int)
    func didReadApplicaton(_ data: [UInt8], connection: TLSConnection, tag: Int)
}

public class TLSSessionManager: NSObject {
    public static var shared = TLSSessionManager()
    public var identity: Identity? = nil
    var sessions: [String : TLSConnection] = [:]
    public var delegate: TLSConnectionDelegate?
    
    public func acceptConnection(_ sock: GCDAsyncSocket) {
        let newConnection = TLSConnection(sock)
        sessions[newConnection.sessionId] = newConnection
        newConnection.handshake()
    }
    
    public func clearConnection(_ connection: TLSConnection) {
        sessions.removeValue(forKey: connection.sessionId)
    }
    
    /// TODO:会话恢复
    func resumeConnection(_ sessionId: [UInt8], new: TLSConnection) -> Bool {
//        if let c = sessions[sessionId] {
//            let p = TLSSecurityParameters(c.cipherSuite)
//            p.preMasterSecret = c.securityParameters.preMasterSecret
//            p.clientRandom = c.securityParameters.clientRandom
//            p.serverRandom = c.securityParameters.serverRandom
//            p.transformParamters()
//            new.sessionId = sessionId
//            new.securityParameters = p
//            return true
//        }
        return false
    }
}
