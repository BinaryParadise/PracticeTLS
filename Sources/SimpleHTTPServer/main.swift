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

let bundle = Bundle(path: "\(Bundle(for: A.self).resourcePath!)/PracticeTLS_SimpleHTTPServer.bundle")!

let identity = PEMFileIdentity(certificateFile: bundle.path(forResource: "Cert/cert.pem", ofType: nil)!, privateKeyFile: bundle.path(forResource: "Cert/private.pem", ofType: nil)!)!

let httpServer = HTTPServer(identity)
httpServer.start(port: 8443).wait()
