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
    var sessions: [Int32 : TLSConnection] = [:]
    
    init() {
        identity = PEMFileIdentity(certificateFile: Bundle.certBundle().path(forResource: "Cert/localhost.crt", ofType: nil)!, privateKeyFile: Bundle.certBundle().path(forResource: "Cert/private.pem", ofType: nil)!)! as! Identity
    }
    
    func acceptConnection(_ connection: TLSConnection) {
        sessions[connection.sock.socket4FD()] = connection
        connection.handshake()
    }
}
