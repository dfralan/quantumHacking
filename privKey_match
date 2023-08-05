//
//  ContentView.swift
//  Hack
//
//  Created by Alan D on 12/05/2023.
//

import SwiftUI
import Foundation
import secp256k1

let PUBKEY_HRP = "npub"
let PRIVKEY_HRP = "nsec"

struct FullKeypair {
    let pubkey: String
    let privkey: String
}

struct Keypair {
    let pubkey: String
    let privkey: String?
    let pubkey_bech32: String
    let privkey_bech32: String?
    
    func to_full() -> FullKeypair? {
        guard let privkey = self.privkey else {
            return nil
        }
        
        return FullKeypair(pubkey: pubkey, privkey: privkey)
    }
    
    init(pubkey: String, privkey: String?) {
        self.pubkey = pubkey
        self.privkey = privkey
        self.pubkey_bech32 = bech32_pubkey(pubkey) ?? pubkey
        self.privkey_bech32 = privkey.flatMap { bech32_privkey($0) }
    }
}

enum Bech32Key {
    case pub(String)
    case sec(String)
}

func generate_new_keypair() -> Keypair {
    let key = try! secp256k1.Signing.PrivateKey()
    let privkey = hex_encode(key.rawRepresentation)
    let pubkey = hex_encode(Data(key.publicKey.xonly.bytes))
    return Keypair(pubkey: pubkey, privkey: privkey)
}

func decode_bech32_key(_ key: String) -> Bech32Key? {
    guard let decoded = try? bech32_decode(key) else {
        return nil
    }
    
    let hexed = hex_encode(decoded.data)
    if decoded.hrp == "npub" {
        return .pub(hexed)
    } else if decoded.hrp == "nsec" {
        return .sec(hexed)
    }
    return nil
}

func hexchar(_ val: UInt8) -> UInt8 {
    if val < 10 {
        return 48 + val;
    }
    if val < 16 {
        return 97 + val - 10;
    }
    assertionFailure("impossiburu")
    return 0
}

func hex_encode(_ data: Data) -> String {
    var str = ""
    for c in data {
        let c1 = hexchar(c >> 4)
        let c2 = hexchar(c & 0xF)

        str.append(Character(Unicode.Scalar(c1)))
        str.append(Character(Unicode.Scalar(c2)))
    }
    return str
}

func bech32_privkey(_ privkey: String) -> String? {
    guard let bytes = hex_decode(privkey) else {
        return nil
    }
    return bech32_encode(hrp: "nsec", bytes)
}

func bech32_pubkey(_ pubkey: String) -> String? {
    guard let bytes = hex_decode(pubkey) else {
        return nil
    }
    return bech32_encode(hrp: "npub", bytes)
}

func bech32_nopre_pubkey(_ pubkey: String) -> String? {
    guard let bytes = hex_decode(pubkey) else {
        return nil
    }
    return bech32_encode(hrp: "", bytes)
}

func privkey_to_pubkey(privkey: String) -> String? {
    guard let sec = hex_decode(privkey) else {
        return nil
    }
    guard let key = try? secp256k1.Signing.PrivateKey(rawRepresentation: sec) else {
        return nil
    }
    return hex_encode(Data(key.publicKey.xonly.bytes))
}

struct ContentView: View {
    @State private var generator = generate_new_keypair()
    @State private var matchingString = ""
    
    var body: some View {
        VStack {
            Text("Matching String: \(matchingString)")
                .padding()
            
            Button(action: {
                matchingString = findMatchingPattern(targetPattern: "c6b18242e67e56820906ca8ad781e71eb2f1a2990a5a892b2bac3f4dae36284f")
            }) {
                Text("Generate Matching String")
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(10)
            }
        }
    }
    
    func generateRandomAlphanumeric(length: Int) -> String {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0..<length).map { _ in characters.randomElement()! })
    }
    
    func findMatchingPattern(targetPattern: String) -> String {
        let patternLength = targetPattern.count
        while true {
            let randomString = generateRandomAlphanumeric(length: patternLength)
            if randomString == targetPattern {
                return randomString
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
