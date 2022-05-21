import { Buffer } from 'buffer';

export class TokenChallenge {
    constructor(
        public tokenType: number,
        public issuerName: string,
        public redemptionNonce: Uint8Array,
        public originInfo: string[],
    ) {}

    static parse(bytes: Uint8Array): TokenChallenge {
        let offset = 0;
        const input = Buffer.from(bytes);

        const type = input.readUint16BE(offset);
        offset += 2;

        let len = input.readUint16BE(offset);
        offset += 2;
        const issuerName = input.subarray(offset, offset + len).toString();
        offset += len;

        len = input.readUInt8(offset);
        offset += 1;
        const redemptionNonce = new Uint8Array(input.subarray(offset, offset + len));
        offset += len;

        len = input.readUint16BE(offset);
        offset += 2;
        const allOriginInfo = input.subarray(offset, offset + len).toString();
        const originInfo = allOriginInfo.split(',');

        return new TokenChallenge(type, issuerName, redemptionNonce, originInfo);
    }

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.alloc(2);
        b.writeUint16BE(this.issuerName.length);
        output.push(b);

        b = Buffer.from(this.issuerName);
        output.push(b);

        b = Buffer.alloc(1);
        b.writeUint8(this.redemptionNonce.length);
        output.push(b);

        b = Buffer.from(this.redemptionNonce);
        output.push(b);

        const allOriginInfo = this.originInfo.join(',');
        b = Buffer.alloc(2);
        b.writeUint16BE(allOriginInfo.length);
        output.push(b);

        b = Buffer.from(allOriginInfo);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

// WWW-Authenticate authorization challenge attributes
const authorizationAttributeChallenge = 'challenge';
const authorizationAttributeMaxAge = 'max-age';
const authorizationAttributeTokenKey = 'token-key';
// const authorizationAttributeNameKey = "origin-name-key"

export interface TokenDetails {
    type: number;
    attester: string;
    challenge: Uint8Array;
    publicKeyEncoded: Uint8Array;
}

export function parseWWWAuthHeader(header: string): TokenDetails[] {
    const challenges = header.split('PrivateToken ');
    const allTokenDetails = new Array<TokenDetails>();

    for (const challenge of challenges) {
        if (challenge.length === 0) {
            continue;
        }

        const attributes = challenge.split(',');
        let challengeBlob = Buffer.alloc(0);
        let tokenKeyEnc = Buffer.alloc(0);

        // parse attributes of a challenge
        for (const attribute of attributes) {
            let [attrKey, attrValue] = attribute.split('=', 2);
            attrKey = attrKey.trim();
            attrValue = attrValue.trim();

            switch (attrKey) {
                case authorizationAttributeChallenge:
                    try {
                        challengeBlob = Buffer.from(attrValue, 'base64url');
                    } catch (e) {
                        try {
                            challengeBlob = Buffer.from(attrValue, 'base64');
                        } catch (e) {
                            return [];
                        }
                    }
                    break;
                case authorizationAttributeTokenKey:
                    try {
                        tokenKeyEnc = Buffer.from(attrValue, 'base64url');
                    } catch (e) {
                        try {
                            tokenKeyEnc = Buffer.from(attrValue, 'base64');
                        } catch (e) {
                            // optional param
                        }
                    }
                    break;
                case authorizationAttributeMaxAge:
                    // not used now
                    break;
            }
        }

        if (challengeBlob.length === 0) {
            continue;
        }

        // Determine type of token
        const type = (challengeBlob[0] << 8) | challengeBlob[1];
        const attester = 'attester.example';
        const details: TokenDetails = {
            type,
            attester,
            challenge: new Uint8Array(challengeBlob),
            publicKeyEncoded: new Uint8Array(tokenKeyEnc),
        };

        allTokenDetails.push(details);
    }

    return allTokenDetails;
}
