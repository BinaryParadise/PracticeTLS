//
//  main.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation
import PracticeTLS

let httpServer = HTTPServer(true)
httpServer.start(port: 8443).wait()
