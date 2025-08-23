//
//  ContentView.swift
//  TestSignInWithApple
//
//  Created by Alvindo Tri Jatmiko on 22/08/25.
//

import AuthenticationServices
import CryptoKit
import SwiftUI

struct ContentView: View {
    @State private var currentNonce: String?

    var body: some View {
        // kalau ada user kembalikan user yang ada kalau tidak maka buat baru
        SignInWithAppleButton(.continue) { request in
            request.requestedScopes = [.email, .fullName]

            let nonce = randomNonceString()
            currentNonce = nonce
            request.nonce = sha256(nonce)
            request.state = UUID().uuidString
        } onCompletion: { result in
            switch result {
            case .success(let auth):
                handle(auth)
            case .failure(let error):
                print("Continue with Apple failed: \(error)")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: 100)
        .padding()
    }

    private func handle(_ auth: ASAuthorization) {
        guard
            let credential = auth.credential
                as? ASAuthorizationAppleIDCredential,
            let identityTokenData = credential.identityToken,
            let identityToken = String(
                data: identityTokenData,
                encoding: .utf8
            ),
            let authorizationCodeData = credential.authorizationCode,
            let authorizationCode = String(
                data: authorizationCodeData,
                encoding: .utf8
            ),
            let nonce = currentNonce
        else { return }

        let name = [
            credential.fullName?.givenName, credential.fullName?.familyName,
        ]
        .compactMap { $0 }.joined(separator: " ").nilIfEmpty
        let body = Payload(
            id_token: identityToken,
            authorization_code: authorizationCode,
            raw_nonce: nonce,
            full_name: name,
            email: credential.email
        )
        print(body)

        if let token = String(data: identityTokenData, encoding: .utf8) {

            if let payload = decode(jwtToken: token) {
                print("JWT payload:", payload)
                if let sub = payload["sub"] as? String {
                    print("Apple user id:", sub)
                }
                if let email = payload["email"] as? String {
                    print("Email (mungkin relay):", email)
                }
                if let exp = payload["exp"] as? Double {
                    let expDate = Date(timeIntervalSince1970: exp)
                    print("Token exp:", expDate)
                }
            }
        }
    }

    func sha256(_ input: String) -> String {
        let inputData = Data(input.utf8)
        let hashed = SHA256.hash(data: inputData)
        return hashed.compactMap { String(format: "%02x", $0) }.joined()
    }

    func randomNonceString(length: Int = 32) -> String {
        precondition(length > 0)
        let charset: [Character] =
            Array(
                "0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._"
            )
        var result = ""
        var remaining = length

        while remaining > 0 {
            var random: UInt8 = 0
            let err = SecRandomCopyBytes(kSecRandomDefault, 1, &random)
            if err != errSecSuccess { fatalError("Tidak bisa membuat nonce.") }
            if random < charset.count {
                result.append(charset[Int(random)])
                remaining -= 1
            }
        }
        return result
    }

    // Decode bagian tengah JWT (payload) jadi dictionary
    func decode(jwtToken jwt: String) -> [String: Any]? {
        let segments = jwt.split(separator: ".")
        guard segments.count >= 2 else { return nil }

        let base64String = String(segments[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Tambahkan padding jika kurang
        let paddedLength = base64String.count + (4 - base64String.count % 4) % 4
        let padded = base64String.padding(
            toLength: paddedLength,
            withPad: "=",
            startingAt: 0
        )

        guard let data = Data(base64Encoded: padded) else { return nil }
        let json = try? JSONSerialization.jsonObject(with: data, options: [])
        return json as? [String: Any]
    }

}

struct Payload: Codable {
    let id_token: String
    let authorization_code: String
    let raw_nonce: String
    let full_name: String?
    let email: String?
}

extension String {
    fileprivate var nilIfEmpty: String? { isEmpty ? nil : self }
}

#Preview {
    ContentView()
}
