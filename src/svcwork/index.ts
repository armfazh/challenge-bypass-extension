import { IssuerConfig, PublicVerifClient } from './pp/pubVerifIssuer'
import { Token, TokenChallenge, TokenDetails, TokenResponse, parseWWWAuthHeader } from './pp/authScheme'

const issuerConfigURI = '/.well-known/token-issuer-directory';

export async function fetchPublicVerifToken(params: TokenDetails): Promise<Token> {
    // Fetch issuer URL
    const tokenChallenge = TokenChallenge.parse(params.challenge);
    const res = await fetch('https://' + tokenChallenge.issuerName + issuerConfigURI);
    const issuerConfig: IssuerConfig = await res.json()

    // Create a TokenRequest.
    const client = new PublicVerifClient(params.publicKeyEncoded);
    const [finData, tokenRequest] = await client.createTokenRequest(params.challenge);

    // Send TokenRequest to Attester (fetch w/POST).
    const httpResponse = await fetch(issuerConfig['issuer-request-uri'], {
        method: 'POST',
        headers: { 'Content-Type': 'message/token-request' },
        body: tokenRequest.serialize().buffer,
    });

    // Receive a TokenResponse,
    const tokenResponse: TokenResponse = { blindSig: new Uint8Array(await httpResponse.arrayBuffer()) };

    // Produce a token by Finalizing the TokenResponse.
    const token = client.finalize(finData, tokenResponse);

    return token;
}

const BasicPublicTokenType = 0x0002
const RateLimitedTokenType = 0x0003
const TokenStore = new Array()

chrome.webRequest.onHeadersReceived.addListener(
    (
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void => {
        if (details.responseHeaders === undefined) { return }
        if (details.statusCode !== 401) { return }

        const header = details.responseHeaders.find((h) => h.name.toLowerCase() == 'www-authenticate');
        if (header === undefined) { return }
        if (header.value === undefined) { return }
        if (!header.value.startsWith('PrivateToken')) { return }

        // Parse challenges from header and extract tokens
        const tokenDetails = parseWWWAuthHeader(header.value)

        for (const d of tokenDetails) {
            switch (d.type) {
                case BasicPublicTokenType:
                    fetchPublicVerifToken(d)
                        .then((token) => {
                            chrome.storage.local.set({ "token": token })
                            console.log("new token stored")
                        })
                        .catch(e => {
                            console.log("cannot fetch token: ", e)
                        })
                    break
                case RateLimitedTokenType:
                    // todo
                    break
            }
        }

        // This request will be retried (i.e., it will be redirected to
        // the same url), and the OnBeforeSendHeaders handler will include
        // a token in the request headers.
        return { redirectUrl: details.url };
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'blocking'],
);

chrome.webRequest.onBeforeSendHeaders.addListener(
    (details: chrome.webRequest.WebRequestHeadersDetails): chrome.webRequest.BlockingResponse | void => {
        if (TokenStore.length === 0) { return }

        // const stored = (async () => { return await chrome.storage.local.get("token") })()
        // console.log(stored)

        const token = TokenStore.pop()
        const encodedToken = Buffer.from(token.serialize()).toString('base64');
        const headerWithToken = {
            name: 'Authorization',
            value: 'PrivateToken token=' + encodedToken,
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
