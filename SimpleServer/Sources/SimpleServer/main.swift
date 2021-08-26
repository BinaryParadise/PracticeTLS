//
//  main.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation
import PracticeTLS

class A {
    
}

let bundle = Bundle(path: "\(Bundle(for: A.self).resourcePath!)/SimpleServer_SimpleServer.bundle")!

let identity = PEMFileIdentity(certificateFile: bundle.path(forResource: "Cert/localhost.crt", ofType: nil)!, privateKeyFile: bundle.path(forResource: "Cert/private.pem", ofType: nil)!)!

let httpServer = HTTPServer(identity)
httpServer.start(port: 8443).wait()
