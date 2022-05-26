import { PublicVerifClient, Token, TokenResponse } from './pubVerifToken';
import { TokenChallenge, TokenDetails, parseWWWAuthHeader } from './httpAuthScheme';
import { convertPSSToEnc, uint8ToB64URL } from './util';

const issuerConfigURI = '/.well-known/token-issuer-directory';

export interface IssuerConfig {
    'issuer-token-window': number;
    'issuer-request-uri': string;
    'issuer-request-key-uri': string;
    'origin-name-key-uri': string;
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
    const saltLen = 48 // For SHA-384
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

interface AppState {
    requestId: string;
    origin: string;
    tokenDetails: TokenDetails[];
}

declare global {
    interface Window {
        TokenStore: Map<string, AppState>;
    }
}

window.TokenStore = new Map<string, AppState>();

const BasicPublicTokenType = 0x0002;
const RateLimitedTokenType = 0x0003;

chrome.webRequest.onHeadersReceived.addListener(
    (
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void => {
        if (details.responseHeaders === undefined) {
            return;
        }
        if (details.statusCode !== 401) {
            return;
        }

        const header = details.responseHeaders.find(
            (h) => h.name.toLowerCase() == 'www-authenticate',
        );

        if (header === undefined
            || header.value === undefined
            || !header.value.startsWith('PrivateToken')) { return; }

        console.log('URL: ', details.url, details.requestId);
        // Parse challenges from header and extract tokens
        const tokenDetails = parseWWWAuthHeader(header.value);
        const value = {
            requestId: details.requestId,
            origin: details.url,
            tokenDetails: tokenDetails,
        };
        window.TokenStore.set(details.requestId, value);
        console.log('token details stored');
        // This request will be retried (i.e., it will be redirected to
        // the same url), and the OnBeforeSendHeaders handler will include
        // a token in the request headers.
        return { redirectUrl: details.url };
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'blocking'],
);

export async function tokenRedemption(
    details: chrome.webRequest.WebRequestHeadersDetails,
    t: Token,
) {
    const headers = new Headers();
    if (details.requestHeaders) {
        details.requestHeaders.forEach((h) => headers.append(h.name, h.value || ''))
    }

    const encodedToken = uint8ToB64URL(t.serialize());
    headers.append('Authorization', 'PrivateToken token=' + encodedToken);

    const res = await fetch(details.url, { headers })

    const text = await res.text()
    console.log("Body recovered: ", text.substring(0, 12))
}

chrome.webRequest.onBeforeSendHeaders.addListener(
    (
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void => {

        // Aqui hay dos casos
        // Uno.
        //    Detectar que el redirect vino de onHeadersReceived
        //    Y crear tokens con el Issuer
        //    Cancelar esta request.
        //
        // Dos
        //    Detectar que el redirect vino de aqui mismo, luego de
        //    haber creador tokens con el issuer.
        //    Apendejar 1 token a los headers de la request
        //    Continuar

        console.log('URL: ', details.url, details.requestId);

        const state = window.TokenStore.get(details.requestId);
        if (!state) {
            return;
        }

        if (state.requestId !== details.requestId) {
            return;
        }

        for (const d of state.tokenDetails) {
            switch (d.type) {
                case BasicPublicTokenType:
                    fetchPublicVerifToken(d)
                        .then((token) => {
                            console.log('creo 1 token', token);
                            tokenRedemption(details, token)
                            // const encodedToken = uint8ToB64URL(token.serialize());
                            // const headerWithToken = {
                            //     name: 'Authorization',
                            //     value: 'PrivateToken token=' + encodedToken,
                            // };
                            // manual redirect
                            // chrome.tabs.update(details.tabId, { url: details.url });
                        })
                        .catch((e) => {
                            console.log('cannot fetch token: ', e);
                        });
                    break;
                case RateLimitedTokenType:
                    // todo
                    break;
            }
        }
        window.TokenStore.delete(details.requestId);

        // Cancel this redirect because this function is syncronous and it will
        // not wait for the async call for fetching tokens.
        return { cancel: true };
    },
    { urls: ['<all_urls>'] },
    ['requestHeaders', 'blocking', 'extraHeaders'],
);
