import { blind, blindSign, finalize } from '../blindrsa';

export interface IssuerConfig {
    'issuer-token-window': number;
    'issuer-request-uri': string;
    'issuer-request-key-uri': string;
    'origin-name-key-uri': string;
}

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
