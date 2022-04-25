import {
    PublicVerifClient,
    PublicVerifToken,
    parseIssuerConfig,
    parseTokenChallenge,
} from './pubverif';

import { Buffer } from 'buffer';

// WWW-Authenticate authorization challenge attributes
const authorizationAttributeChallenge = 'challenge';
const authorizationAttributeMaxAge = 'max-age';
const authorizationAttributeTokenKey = 'token-key';
// const authorizationAttributeNameKey = "origin-name-key"

const issuerConfigURI = '/.well-known/token-issuer-directory';
// Type of authorization token
const privateTokenType = 'PrivateToken';

// Type of Privacy Pass token
const basicPublicTokenType = 0x0002;
const rateLimitedTokenType = 0x0003;

interface Params {
    attester: string;
    challenge: Uint8Array;
    publicKeyEncoded: Uint8Array;
}

const TokenStore = new Array();

export function fetchRateLimitedToken(
    _clientOriginSecret: Uint8Array,
    _id: number,
    _origin: string,
    _params: Params,
) {
    return;
}

export async function fetchBasicToken(params: Params): Promise<PublicVerifToken> {
    // Fetch issuer URL
    const tokenChallenge = parseTokenChallenge(params.challenge);
    const res = await fetch('https://' + tokenChallenge.IssuerName + issuerConfigURI);
    const issuerConfig = parseIssuerConfig(new Uint8Array(await res.arrayBuffer()));
    // Create a TokenRequest.
    const client = new PublicVerifClient(params.publicKeyEncoded);
    const [finData, tokenRequest] = await client.createTokenRequest(params.challenge);
    // Send TokenRequest to Attester (fetch w/POST).
    const httpResponse = await fetch(issuerConfig.RequestURI, {
        method: 'POST',
        body: tokenRequest.serialize(),
    });
    // Receive a TokenResponse,
    const tokenResponse = { blind_sig: new Uint8Array(await httpResponse.arrayBuffer()) };
    // Produce a token by Finalizing the TokenResponse.
    const token = client.finalize(finData, tokenResponse);

    return token;
}

chrome.webRequest.onHeadersReceived.addListener(
    (
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void => {
        if (details.responseHeaders) {
            const header = details.responseHeaders.find((h) => h.name == 'www-authenticate');

            if (header === undefined) {
                return;
            }
            if (header.value == undefined) {
                return;
            }
            if (!header.value.startsWith(privateTokenType)) {
                return;
            }

            // console.log('header', header.value);

            // parse challenges from header and extract tokens
            const challenges = header.value.split(privateTokenType);
            // console.log('challenges', challenges);

            for (const challenge of challenges) {
                if (challenge.length == 0) {
                    continue;
                }

                const attributes = challenge.trim().split(',');
                let challengeBlob = Buffer.alloc(0);
                let tokenKeyEnc = Buffer.alloc(0);

                // parse attributes of a challenge
                for (const attribute of attributes) {
                    let [attrKey, attrValue] = attribute.split('=', 2);
                    attrKey = attrKey.trim();
                    attrValue = attrValue.trim();
                    // console.log('atribute (k,v)', attrKey, attrValue);

                    switch (attrKey) {
                        case authorizationAttributeChallenge:
                            try {
                                challengeBlob = Buffer.from(attrValue, 'base64url');
                            } catch (e) {
                                try {
                                    challengeBlob = Buffer.from(attrValue, 'base64');
                                } catch (e) {
                                    return;
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

                // console.log('challenge #');
                // console.log('challengeBlob', challengeBlob);
                // console.log('tokenKeyEnc', tokenKeyEnc);

                // Determine type of token
                const type = (challengeBlob[0] << 8) | challengeBlob[1];
                // console.log('type', type);
                const attester = 'attester.example';
                const params: Params = {
                    attester,
                    challenge: new Uint8Array(challengeBlob.buffer),
                    publicKeyEncoded: new Uint8Array(tokenKeyEnc!.buffer),
                };
                // console.log('params', params);

                // Create and store a token in TokenStore
                switch (type) {
                    case rateLimitedTokenType:
                        // token = fetchRateLimitedToken(clientOriginSecret, id, origin, params)
                        // tokenStore.push(token)
                        break;
                    case basicPublicTokenType:
                        const token = fetchBasicToken(params);
                        TokenStore.push(token);
                        break;
                }
            }

            // This request will be retried (i.e., it will be redirected to
            // the same url), and the OnBeforeSendHeaders handler will include
            // a token in the request headers.
            return { redirectUrl: details.url };
        }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'blocking'],
);

chrome.webRequest.onBeforeSendHeaders.addListener(
    (
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void => {
        // there are no tokens
        if (TokenStore.length === 0) {
            return;
        }

        const token = TokenStore.pop();
        const encodedToken = Buffer.from(token.serialize()).toString('base64');
        const headerWithToken = {
            name: 'Authorization',
            value: privateTokenType + ' token=' + encodedToken,
        };

        let headers = new Array();
        headers = headers.concat(details.requestHeaders);
        headers.push(headerWithToken);

        return {
            requestHeaders: headers,
        };
    },
    { urls: ['<all_urls>'] },
    ['requestHeaders', 'blocking', 'extraHeaders'],
);

export { };
