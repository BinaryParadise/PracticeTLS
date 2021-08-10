//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation
import CryptorRSA

public class RSAUtils {
    public static var shared = RSAUtils()
    private var privateKey: CryptorRSA.PrivateKey?
    private var publicKey: CryptorRSA.PublicKey?
    public init() {
        do {
            let bundle = Bundle.certBundle()
            //rsa = RSA(filenameOfPulbicKey: bundle.path(forResource: "Cert/public.pem", ofType: nil)!, filenameOfPrivateKey: bundle.path(forResource: "Cert/private.pem", ofType: nil)!)
            publicKey = try CryptorRSA.createPublicKey(with: Data(contentsOf: URL(fileURLWithPath: bundle.path(forResource: "Cert/public.pem", ofType: nil)!)))
            privateKey = try CryptorRSA.createPrivateKey(with: Data(contentsOf: URL(fileURLWithPath: bundle.path(forResource: "Cert/private.pem", ofType: nil)!)))
        } catch {
            print("公钥私钥加载失败：\(error)")
        }
    }
        
    public func encrypted(_ data: Data) -> Data? {
        guard let publicKey = publicKey else { return nil }
        let plainText = CryptorRSA.createPlaintext(with: data)
        do {
            return try plainText.encrypted(with: publicKey, algorithm: .sha1)?.data
        } catch {
            LogError("\(error)")
        }
        return nil
    }
    
    public func decrypted(_ data: Data) -> Data? {
        guard let privateKey = privateKey else { return nil }
        do {
            let encryptedText = try CryptorRSA.createEncrypted(with: data.digest(using: .sha1))
            return try encryptedText.decrypted(with: privateKey, algorithm: .sha1)?.data
        } catch {
            LogError("\(error)")
        }
        return nil
    }
}
