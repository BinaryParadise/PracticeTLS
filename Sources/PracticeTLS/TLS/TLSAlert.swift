//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/24.
//

import Foundation

class TLSAlert: TLSMessage {
    let level : TLSAlertLevel
    let alertType : TLSAlertType
    
    init(alert: TLSAlertType, alertLevel: TLSAlertLevel) {
        self.level = alertLevel
        self.alertType = alert
        
        super.init(.alert)
        type = .alert
    }
    
    override init?(stream: DataStream, context: TLSConnection) {
        stream.read(count: 5)
        level = TLSAlertLevel(rawValue: stream.readByte() ?? 0) ?? .warning
        alertType = TLSAlertType(rawValue: stream.readByte() ?? 0) ?? .accessDenied
        super.init(.alert)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(level.rawValue)
        bytes.append(alertType.rawValue)
        return bytes
    }
}

enum TLSAlertLevel : UInt8
{
    case warning = 1
    case fatal = 2
}

enum TLSAlertType : UInt8
{
    case unknown = 255
    case closeNotify = 0
    case unexpectedMessage = 10
    case badRecordMAC = 20
    case decryptionFailed_RESERVED = 21
    case recordOverflow = 22
    case decompressionFailure = 30
    case handshakeFailure = 40
    case noCertificate = 41 // SSLv3 only
    case badCertificate = 42
    case unsupportedCertificate = 43
    case certificateRevoked = 44
    case certificateExpired = 45
    case certificateUnknown = 46
    case illegalParameter = 47
    case unknownCA = 48
    case accessDenied = 49
    case decodeError = 50
    case decryptError = 51
    case exportRestriction = 60
    case protocolVersion = 70
    case insufficientSecurity = 71
    case internalError = 80
    case userCancelled = 90
    case noRenegotiation = 100
    case missingExtension = 109
    case unsupportedExtension = 110
    case certificateUnobtainable = 111
    case unrecognizedName = 112
    case badCertificateStatusResponse = 113
    case badCertificateHashValue = 114
    case unknownPSKIdentity = 115
    case certificateRequired = 116
    case noApplicationProtocol = 120

}
