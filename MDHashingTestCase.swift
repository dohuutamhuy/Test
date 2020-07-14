//
//  TestHashingFunction.swift
//  iOSUnitTestSwift
//
//  Created by Huy Do on 3/11/20.
//  Copyright © 2020 Kryptowire. All rights reserved.
//

import Foundation
import CommonCrypto

func MDHashingTest(string: String) -> String{
    //setup string
    var result = "MD Hashing Test"
    //Hashing
    result = result + "\nHmac: " + HMAC(string: string, keyString: "Pikachu")
    result = result + "\n\nHmac: " + HMAC_2(string: string, keyString: "Pikachu")
    result = result + "\n\nMD2: " + MD2(string: string)
    result = result + "\n\nMD2: " + MD2_2(string: string)
    result = result + "\n\nMD4: " + MD4(string: string)
    result = result + "\n\nMD4: " + MD4_2(string: string)
    result = result + "\n\nMD5: " + MD5(string: string)
    result = result + "\n\nMD5: " + MD5_2(string: string)
    return result
}


func HMAC(string: String, keyString: String) -> String {
    let key = keyString.data(using: .utf8)!
    let message = string.data(using: .utf8)!
    let digestLen = Int(CC_SHA1_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    key.withUnsafeBytes() { (buffer: UnsafePointer<UInt8>) in
        message.withUnsafeBytes { (data: UnsafePointer<UInt8>) in            
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), buffer, size_t(key.count), data, size_t(message.count), result)
        }
    }
    
    let hash = NSMutableString()
       for i in 0..<digestLen {
           hash.appendFormat("%02x", result[i])
       }
    return String(format: hash as String)
}

func HMAC_2(string: String, keyString: String) -> String {
    let message = string.data(using: .utf8)!
    let context = UnsafeMutablePointer<CCHmacContext>.allocate(capacity: 1)
    defer { context.deallocate() }
    let key = keyString.data(using: .utf8)!
    let digestLen = Int(CC_SHA1_DIGEST_LENGTH)
    
    key.withUnsafeBytes() { (buffer: UnsafePointer<UInt8>) in
        CCHmacInit(context, CCHmacAlgorithm(kCCHmacAlgSHA1), buffer, size_t(key.count))
    }
    
    message.withUnsafeBytes { (buffer: UnsafePointer<UInt8>) in
        CCHmacUpdate(context, buffer, size_t(message.count))
    }
        
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    CCHmacFinal(context, result)
    
    let hash = NSMutableString()
    for i in 0..<digestLen {
        hash.appendFormat("%02x", result[i])
    }
    return String(format: hash as String)
}

func MD2(string: String) -> String {
    let str = string.cString(using: String.Encoding.utf8)
    let strLen = CC_LONG(string.lengthOfBytes(using: String.Encoding.utf8))
    let digestLen = Int(CC_MD2_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    
    CC_MD2(str!, strLen, result)

    let hash = NSMutableString()
    for i in 0..<digestLen {
        hash.appendFormat("%02x", result[i])
    }
    
    result.deallocate()
    
    return String(format: hash as String)
}

func MD2_2(string: String) -> String {
    let str = string.cString(using: String.Encoding.utf8)!
    let strLen = CC_LONG(string.lengthOfBytes(using: String.Encoding.utf8))
    let context = UnsafeMutablePointer<CC_MD2_CTX>.allocate(capacity: 1)
    let digestLen = Int(CC_MD2_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    CC_MD2_Init(context)
    CC_MD2_Update(context, str, strLen)
    CC_MD2_Final(result, context)
    
    let hash = NSMutableString()
    for i in 0..<digestLen {
        hash.appendFormat("%02x", result[i])
    }
    
    result.deallocate()
    
    return String(format: hash as String)
}

func MD4(string: String) -> String {
    let str = string.cString(using: String.Encoding.utf8)
    let strLen = CC_LONG(string.lengthOfBytes(using: String.Encoding.utf8))
    let digestLen = Int(CC_MD4_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    
    CC_MD4(str!, strLen, result)

    let hash = NSMutableString()
    for i in 0..<digestLen {
        hash.appendFormat("%02x", result[i])
    }
    
    result.deallocate()
    
    return String(format: hash as String)
}

func MD4_2(string: String) -> String {
    let str = string.cString(using: String.Encoding.utf8)!
    let strLen = CC_LONG(string.lengthOfBytes(using: String.Encoding.utf8))
    let context = UnsafeMutablePointer<CC_MD4_CTX>.allocate(capacity: 1)
    let digestLen = Int(CC_MD4_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    CC_MD4_Init(context)
    CC_MD4_Update(context, str, strLen)
    CC_MD4_Final(result, context)
    
    let hash = NSMutableString()
    for i in 0..<digestLen {
        hash.appendFormat("%02x", result[i])
    }
    
    result.deallocate()
    
    return String(format: hash as String)
}

func MD5(string: String) -> String {
    let str = string.cString(using: String.Encoding.utf8)
    let strLen = CC_LONG(string.lengthOfBytes(using: String.Encoding.utf8))
    let digestLen = Int(CC_MD5_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    
    CC_MD5(str!, strLen, result)

    let hash = NSMutableString()
    for i in 0..<digestLen {
        hash.appendFormat("%02x", result[i])
    }
    
    result.deallocate()
    
    return String(format: hash as String)
}

func MD5_2(string: String) -> String {
    let str = string.cString(using: String.Encoding.utf8)!
    let strLen = CC_LONG(string.lengthOfBytes(using: String.Encoding.utf8))
    let context = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)
    let digestLen = Int(CC_MD5_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    CC_MD5_Init(context)
    CC_MD5_Update(context, str, strLen)
    CC_MD5_Final(result, context)
    
    let hash = NSMutableString()
    for i in 0..<digestLen {
        hash.appendFormat("%02x", result[i])
    }
    
    result.deallocate()
    
    return String(format: hash as String)
}
