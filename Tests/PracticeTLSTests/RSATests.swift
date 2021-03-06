//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/10/15.
//

import Foundation
import XCTest
@testable import PracticeTLS

let priKey = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwlrILgRpHj+i847BwDovZxYAWwjIejcogloLjwSz3fecsHbQ
5sG+Z4wotx50OefEtOIoZnh5T6/7HO9ZI0eQyCNOwrDCmACAcrEoyzk/0dytFyYL
PcdRgC+foSQ5Bgor3QmlwojRHxUP5KTl90eftVI/GyCTtzHIewOQk6cu8W4o531g
YDGuU1lrVaGiyqQsQrNZ38HoO+Iv+WKyBjJSC1DYoYe+w2tra3H+PWRTsNCbHDAD
zX36uG2lD/msqC08tl1G9yTK1Jri5MlB1+BwHcj127peKDjpq7ydrcxCtflzFueT
q/wpc3D7kUrFbOZba8WMPRnjxGllqTZC3zUlBwIDAQABAoIBAHwpmvErCCy24tdO
QCEaCuaEe72sosbRLiP4eqHnkzEe2w8xGMwSwh1MwUYbQo0rr9MPGFg+ZuGtv3MA
xaVwNuJlDA/89JQ+3dBntXP/IvJjVIERYOUazMpjoktD5Noi7VrMqwTYeyCsR/b+
EZwkObeQz5f4++Vw/G76HAb4K1k4tVj+Bhqtq228ELbrcbEN9UKSCVdo/zAvw0B/
qLvXi8j2qu5ONo0zeOy/PGsyGWGr2++/nqraAuDj6wPBzwIyz2sIA61gitjjBU5i
xA+dHbEh+ES4KEL1c2BfavoioG+Ac2DNfPX8mTB/TE6rma97myaahKxZGrbAtZQY
BLA8RgECgYEA72/quC9dhHgXP/gSweBXk2vnPg7OFZVh2rrEDnY+qch0qpV5hG/1
vZPgFh/KtZ78ZAd3sb2EtS1/OfwvhGBbCbhzO+LR642kAudcAz6Zj5bNjW3EKRvG
wvhr+fs+xAOole9hLUd8V5Tww+541hgNPTDqxfBCrFkaC/bSnTAeYccCgYEAz8yE
y4DnsUI0XDbEXTTyVWGTROvEs4IjkWKBhs2PL9Pnh2j2vjsJ1OAa0H+74RwkgBcF
kWrhGMRj3YR2OcSRvjHK8NojIQ9cPT0wFcObLNisWggqay3eiLEYwd5x14OrXVrI
hewCstmU8+A1sjeKLTWDOFRWn3zylHCJ/gYnIsECgYBzru8I7lmQlzUkgwcNBQdL
AudG5IBNjU8qDvKKyjaccW1svatogW+JmNi718Bo39exvKnoBlkH8GN38JBEtQlH
OQbz+DLUTCrh/EZIiwZGieXmXxJXikQOD1ib/vfkXKAnUPDyn4dECYIKKD3ZsuUy
m1/TIrIT8zjSbv5zU7xaIQKBgQCsLDv3VdYjM8SohyRKSh1kCxX3rBXt2i1YP7Ms
m1NBgKU8uAaBde9ed1UgXkWwbh38F5cgdtsNJ2PLXf6LPMi5Ow54Y3Vp5g06HGGk
Fs+S5/BeJJfo+DeDMKFfuMzAkbNCBX9SH0vZHpjhPGuhP414ifcwjAi92swvm9Nq
K3TvwQKBgA2oTkE2FBw9UfjSGo/uGK5Ctcy2N4AhCoc6pJU1DMuhTmAFlU600XoH
d3RL1fupaK4dyAkxlAvyNfG6JbsPYa3EXOThnXhZHS6c8Fpe9UkcGpR+VSeCJGue
lziHR3yn73gaK+sgNdZVbsW4jHACydlJYKLVlhcch6KkgeyIjgnz
-----END RSA PRIVATE KEY-----
"""
let pubKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwlrILgRpHj+i847BwDov
ZxYAWwjIejcogloLjwSz3fecsHbQ5sG+Z4wotx50OefEtOIoZnh5T6/7HO9ZI0eQ
yCNOwrDCmACAcrEoyzk/0dytFyYLPcdRgC+foSQ5Bgor3QmlwojRHxUP5KTl90ef
tVI/GyCTtzHIewOQk6cu8W4o531gYDGuU1lrVaGiyqQsQrNZ38HoO+Iv+WKyBjJS
C1DYoYe+w2tra3H+PWRTsNCbHDADzX36uG2lD/msqC08tl1G9yTK1Jri5MlB1+Bw
Hcj127peKDjpq7ydrcxCtflzFueTq/wpc3D7kUrFbOZba8WMPRnjxGllqTZC3zUl
BwIDAQAB
-----END PUBLIC KEY-----
"""

class RSATests: XCTestCase {
    func testSign() throws {
        RSAEncryptor.shared.setup(publicPEM: pubKey, privatePEM: priKey)
        let signed = try RSAEncryptor.shared.sign(data: [1,2,3])
        let ret = try RSAEncryptor.shared.verify(signed: signed, signature: [1,2,3])
        XCTAssertTrue(ret)
    }
    func testEncrypt() throws {
        RSAEncryptor.shared.setup(publicPEM: pubKey, privatePEM: priKey)
        let rsa = RSAEncryptor.shared
        let encrypted = try rsa.encryptData(data: Data([1,2,3]))
        let decrypted = try rsa.decryptData(data: encrypted.bytes)
        XCTAssertEqual(decrypted, [1,2,3])
    }
}
