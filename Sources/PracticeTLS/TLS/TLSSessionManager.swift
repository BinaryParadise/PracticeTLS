//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation

class TLSSessionManager {
    static var shared = TLSSessionManager()
    let identity: Identity
    var sessions: [[UInt8] : TLSConnection] = [:]
    
    init() {
        identity = PEMFileIdentity(certificateFile: Bundle.certBundle().path(forResource: "Cert/localhost.crt", ofType: nil)!, privateKeyFile: Bundle.certBundle().path(forResource: "Cert/private.pem", ofType: nil)!)! as! Identity
    }
    
    func acceptConnection(_ connection: TLSConnection) {
        sessions[connection.sessionId] = connection
        connection.handshake()
    }
    
    /// 会话恢复
    func resumeConnection(_ sessionId: [UInt8], new: TLSConnection) -> Bool {
        if let c = sessions[sessionId] {
            let p = TLSSecurityParameters(c.cipherSuite)
            p.preMasterSecret = c.securityParameters.preMasterSecret
            p.clientRandom = c.securityParameters.clientRandom
            p.serverRandom = c.securityParameters.serverRandom
            p.transformParamters()
            new.sessionId = sessionId
            new.securityParameters = p
            return true
        }
        return false
    }
}
