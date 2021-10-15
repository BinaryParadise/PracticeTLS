//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation
import Socket

public protocol TLSConnectionDelegate {
    /// TLS握手完成
    func didHandshakeFinished(_ connection: TLSConnection)
    func didWriteApplication(_ connection: TLSConnection, tag: Int)
    func didReadApplication(_ data: [UInt8], connection: TLSConnection, tag: Int)
}

public class TLSSessionManager: NSObject {
    public static var shared = TLSSessionManager()
    
    public var isDebug: Bool = false
    
    public var identity: Identity? = nil {
        willSet {
            if let pemIdentity = newValue as? PEMFileIdentity {
                try? RSAEncryptor.shared.setup(publicPEM: String(contentsOfFile: pemIdentity.publicPEM), privatePEM: String(contentsOfFile: pemIdentity.privatePEM))
            }
        }
    }
    var sessions: [String : TLSConnection] = [:]
    public var delegate: TLSConnectionDelegate?
    let sema = DispatchSemaphore(value: 1)
    
    public func acceptConnection(_ sock: Socket) {
        let newConnection = TLSConnection(sock)
        newConnection.handshake()
        sema.wait()
        sessions[newConnection.sessionId] = newConnection
        sema.signal()
    }
    
    public func clearConnection(_ connection: TLSConnection) {
        sema.wait()
        sessions.removeValue(forKey: connection.sessionId)
        sema.signal()
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
