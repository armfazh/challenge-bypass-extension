import { TokenChallenge, TokenDetails } from './httpAuthScheme';
import { blind, blindSign, finalize } from '../blindrsa';
import { convertPSSToEnc, uint8ToB64URL } from './util';

import { Buffer } from 'buffer';

export class TokenRequest {
    constructor(
        public tokenType: number,
        public tokenKeyId: number,
        public blindedMsg: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.alloc(1);
        b.writeUint8(this.tokenKeyId);
        output.push(b);

        b = Buffer.from(this.blindedMsg);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

class TokenPayload {
    constructor(
        public tokenType: number,
        public nonce: Uint8Array,
        public context: Uint8Array,
        public keyId: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.from(this.nonce);
        output.push(b);

        b = Buffer.from(this.context);
        output.push(b);

        b = Buffer.from(this.keyId);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

export class Token {
    constructor(public payload: TokenPayload, public authenticator: Uint8Array) {}

    serialize(): Uint8Array {
        return new Uint8Array(Buffer.concat([this.payload.serialize(), this.authenticator]));
    }
}

export class TokenResponse {
    constructor(public blindSig: Uint8Array) {}
    serialize(): Uint8Array {
        return new Uint8Array(this.blindSig);
    }
}

export class PublicVerifClient {
    static TYPE = 0x2;
    private finData?: {
        tokenInput: Uint8Array;
        tokenPayload: TokenPayload;
        tokenRequest: TokenRequest;
        blindInv: Uint8Array;
    };

    constructor(
        private readonly publicKey: CryptoKey,
        private readonly publicKeyEnc: Uint8Array,
        private readonly saltLength: number = 0,
    ) {}

    async createTokenRequest(challenge: Uint8Array): Promise<TokenRequest> {
        // https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-04.html#name-client-to-issuer-request-2
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(await crypto.subtle.digest('SHA-256', challenge));
        const keyId = new Uint8Array(await crypto.subtle.digest('SHA-256', this.publicKeyEnc));
        const tokenPayload = new TokenPayload(PublicVerifClient.TYPE, nonce, context, keyId);
        const tokenInput = tokenPayload.serialize();

        const { blindedMsg, blindInv } = await blind(this.publicKey, tokenInput, this.saltLength);
        const tokenKeyId = keyId[0];
        const tokenRequest = new TokenRequest(PublicVerifClient.TYPE, tokenKeyId, blindedMsg);
        this.finData = { tokenInput, tokenPayload, blindInv, tokenRequest };

        return tokenRequest;
    }

    async finalize(t: TokenResponse): Promise<Token> {
        if (!this.finData) {
            throw new Error('no token request was created yet.');
        }

        const authenticator = await finalize(
            this.publicKey,
            this.finData.tokenInput,
            this.finData.blindInv,
            t.blindSig,
            this.saltLength,
        );
        const token = new Token(this.finData.tokenPayload, authenticator);
        this.finData = undefined;

        return token;
    }
}

export class PublicVerifIssuer {
    static async issue(privateKey: CryptoKey, tokReq: TokenRequest): Promise<TokenResponse> {
        return new TokenResponse(await blindSign(privateKey, tokReq.blindedMsg));
    }
}

const issuerConfigURI = '/.well-known/token-issuer-directory';

export async function tokenRedemption(
    details: chrome.webRequest.WebRequestHeadersDetails,
    t: Token,
) {
    const headers = new Headers();
    if (details.requestHeaders) {
        details.requestHeaders.forEach((h) => headers.append(h.name, h.value || ''));
    }

    const encodedToken = uint8ToB64URL(t.serialize());
    headers.append('Authorization', 'PrivateToken token=' + encodedToken);

    const res = await fetch(details.url, { headers });

    const text = await res.text();
    console.log('Body recovered: ', text.substring(0, 12));
}

export async function fetchPublicVerifToken(params: TokenDetails): Promise<Token> {
    // Fetch issuer URL
    const tokenChallenge = TokenChallenge.parse(params.challenge);
    const res = await fetch('https://' + tokenChallenge.issuerName + issuerConfigURI);
    const issuerConfig = await res.json();
    console.log('issuerConfig: ', issuerConfig);

    // Create a TokenRequest.
    const spkiEncoded = convertPSSToEnc(params.publicKeyEncoded);
    const publicKey = await crypto.subtle.importKey(
        'spki',
        spkiEncoded,
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );
    const saltLen = 48; // For SHA-384
    const client = new PublicVerifClient(publicKey, params.publicKeyEncoded, saltLen);
    const tokenRequest = await client.createTokenRequest(params.challenge);

    // Send TokenRequest to Issuer (fetch w/POST).
    const issuerResponse = await fetch(issuerConfig['issuer-request-uri'], {
        method: 'POST',
        headers: { 'Content-Type': 'message/token-request' },
        body: tokenRequest.serialize().buffer,
    });

    //  Receive a TokenResponse,
    const tokenResponse = new TokenResponse(new Uint8Array(await issuerResponse.arrayBuffer()));

    // Produce a token by Finalizing the TokenResponse.
    const token = client.finalize(tokenResponse);

    return token;
}
