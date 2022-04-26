import { Token, TokenPayload, TokenRequest, TokenResponse } from './authScheme'

function rsabssa_blind(
    _publicKey: Uint8Array,
    _input: Uint8Array,
): {
    blindedMsg: Uint8Array;
    blindInv: Uint8Array;
} {
    const blindedMsg = new Uint8Array();
    const blindInv = new Uint8Array();
    return { blindedMsg, blindInv };
}

function rsabssa_finalize(
    _publicKey: Uint8Array,
    _nonce: Uint8Array,
    _blind_sig: Uint8Array,
    _blind_inv: Uint8Array,
): Uint8Array {
    return new Uint8Array();
}

export interface FinData {
    tokenPayload: TokenPayload;
    tokenRequest: TokenRequest
    blindInv: Uint8Array;
}

export class PublicVerifClient {
    static TYPE = 0x2

    constructor(public readonly publicKeyEnc: Uint8Array) { }

    async createTokenRequest(challenge: Uint8Array): Promise<[FinData, TokenRequest]> {
        // https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-04.html#name-client-to-issuer-request-2
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(await crypto.subtle.digest('SHA-256', challenge));
        const keyId = new Uint8Array(await crypto.subtle.digest('SHA-256', this.publicKeyEnc));
        const tokenPayload = new TokenPayload(PublicVerifClient.TYPE, nonce, context, keyId)
        const tokenInput = tokenPayload.serialize()
        const { blindedMsg, blindInv } = rsabssa_blind(this.publicKeyEnc, tokenInput);

        const tokenKeyId = keyId[0]
        const tokenRequest = new TokenRequest(PublicVerifClient.TYPE, tokenKeyId, blindedMsg);
        const finData = { tokenPayload, blindInv, tokenRequest };

        return [finData, tokenRequest];
    }

    async finalize(f: FinData, t: TokenResponse): Promise<Token> {
        const authenticator = rsabssa_finalize(this.publicKeyEnc, f.tokenPayload.nonce, t.blindSig, f.blindInv);
        return new Token(f.tokenPayload, authenticator);
    }
}

export interface IssuerConfig {
    "issuer-token-window": number
    "issuer-request-uri": string
    "issuer-request-key-uri": string
    "origin-name-key-uri": string
}
