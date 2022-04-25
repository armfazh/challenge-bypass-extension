function joinAll(a: Uint8Array[]): Uint8Array {
    let size = 0;
    for (let i = 0; i < a.length; i++) {
        size += a[i as number].length;
    }
    const ret = new Uint8Array(new ArrayBuffer(size));
    for (let i = 0, offset = 0; i < a.length; i++) {
        ret.set(a[i as number], offset);
        offset += a[i as number].length;
    }
    return ret;
}

function rsabssa_blind(
    _publicKey: Uint8Array,
    _input: Uint8Array,
): {
    blinded_msg: Uint8Array;
    blind_inv: Uint8Array;
} {
    const blinded_msg = new Uint8Array();
    const blind_inv = new Uint8Array();
    return { blinded_msg, blind_inv };
}

function rsabssa_finalize(
    _publicKey: Uint8Array,
    _nonce: Uint8Array,
    _blind_sig: Uint8Array,
    _blind_inv: Uint8Array,
): Uint8Array {
    return new Uint8Array();
}

export class PublicVerifToken {
    constructor(
        public nonce: Uint8Array,
        public challenge_digest: Uint8Array,
        public token_key_id: Uint8Array,
        public authenticator: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        return new Uint8Array();
    }
}

export interface FinData {
    nonce: Uint8Array;
    blind_inv: Uint8Array;
    key_id: Uint8Array;
}

export class PublicVerifClient {
    constructor(public readonly publicKey: Uint8Array) {}

    async createTokenRequest(challenge: Uint8Array): Promise<[FinData, TokenRequest]> {
        // https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-04.html#name-client-to-issuer-request-2
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(await crypto.subtle.digest('SHA-256', challenge));
        const key_id = new Uint8Array();
        const token_input = joinAll([Uint8Array.from([0x0002]), nonce, context, key_id]);
        const { blinded_msg, blind_inv } = rsabssa_blind(this.publicKey, token_input);

        const finData = {
            nonce,
            blind_inv,
            key_id,
        };
        const tokenRequest = new TokenRequest(2, key_id, blinded_msg);

        return [finData, tokenRequest];
    }

    async finalize(f: FinData, t: TokenResponse): Promise<PublicVerifToken> {
        const authenticator = rsabssa_finalize(this.publicKey, f.nonce, t.blind_sig, f.blind_inv);
        const challenge = new Uint8Array();
        const challenge_digest = new Uint8Array(await crypto.subtle.digest('SHA-256', challenge));
        return new PublicVerifToken(f.nonce, challenge_digest, f.key_id, authenticator);
    }
}
export class TokenRequest {
    constructor(
        public token_type: number,
        public token_key_id: Uint8Array, //"token_key_id" is the least significant byte of the key_id.
        public blinded_msg: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        return new Uint8Array();
    }
}
export interface TokenResponse {
    blind_sig: Uint8Array;
}

export interface TokenChallenge {
    TokenType: number;
    IssuerName: string;
    RedemptionNonce: Uint8Array;
    OriginInfo: string[];
}
export function parseTokenChallenge(_b: Uint8Array): TokenChallenge {
    return {
        TokenType: 2,
        IssuerName: '',
        RedemptionNonce: new Uint8Array(),
        OriginInfo: [''],
    };
}
export interface IssuerConfig {
    TokenWindow: number;
    RequestURI: string;
    RequestKeyURI: string;
    OriginNameKeyURI: string;
}
export function parseIssuerConfig(_b: Uint8Array): IssuerConfig {
    return {
        TokenWindow: 0,
        RequestURI: '',
        RequestKeyURI: '',
        OriginNameKeyURI: '',
    };
}
