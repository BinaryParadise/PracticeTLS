//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation
import CocoaAsyncSocket

public protocol TLSConnectionDelegate {
    func onReceive(application data: [UInt8], userInfo: [String : AnyHashable]) -> [UInt8]?
}

public class TLSSessionManager: NSObject {
    public static var shared = TLSSessionManager()
    public var identity: Identity? = nil
    var sessions: [Int : TLSConnection] = [:]
    public var delegate: TLSConnectionDelegate?
    
    public func acceptConnection(_ sock: GCDAsyncSocket) {
        let newConnection = TLSConnection(sock)
        sessions[newConnection.hash] = newConnection
        newConnection.handshake()
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
