import { Buffer } from "buffer"

// WWW-Authenticate authorization challenge attributes
const authorizationAttributeChallenge = "challenge"
const authorizationAttributeMaxAge = "max-age"
const authorizationAttributeTokenKey = "token-key"
// const authorizationAttributeNameKey = "origin-name-key"

// Type of authorization token
const privateTokenType = "PrivateToken"

// Type of Privacy Pass token
const basicPublicTokenType = 0x0002
const rateLimitedTokenType = 0x0003

interface Params {
    attester: string,
    challengeBlob: string,
    tokenKeyEnc?: string
}

const TokenStore = new Array();


export function fetchRateLimitedToken(
    _clientOriginSecret: Uint8Array, _id: number, _origin: string, _params: Params
) { }

export function fetchBasicToken(_params: Params) { }


chrome.webRequest.onHeadersReceived.addListener(
    (details: chrome.webRequest.WebResponseHeadersDetails): chrome.webRequest.BlockingResponse | void => {
        if (details.responseHeaders) {
            const header = details.responseHeaders.find((h) => h.name == "www-authenticate");

            if (header === undefined) { return }
            if (header.value == undefined) { return }
            if (!header.value.startsWith(privateTokenType)) { return }

            console.log("header", header.value)

            // parse challenges from header and extract tokens
            const challenges = header.value.split(privateTokenType)
            console.log("challenges", challenges)

            for (const challenge of challenges) {
                if (challenge.length == 0) { continue }

                const attributes = challenge.trim().split(",")
                let challengeBlob;
                let tokenKeyEnc;

                // parse attributes of a challenge
                for (const attribute of attributes) {
                    let [attrKey, attrValue] = attribute.split("=", 2)
                    attrKey = attrKey.trim()
                    attrValue = attrValue.trim()
                    console.log("atribute (k,v)", attrKey, attrValue)

                    switch (attrKey) {
                        case authorizationAttributeChallenge:
                            try {
                                challengeBlob = Buffer.from(attrValue, "base64url")
                            } catch (e) {
                                try {
                                    challengeBlob = Buffer.from(attrValue, "base64")
                                } catch (e) {
                                    return
                                }
                            }
                            break
                        case authorizationAttributeTokenKey:
                            try {
                                tokenKeyEnc = Buffer.from(attrValue, "base64url")
                            } catch (e) {
                                try {
                                    tokenKeyEnc = Buffer.from(attrValue, "base64")
                                } catch (e) {
                                    // optional param
                                }
                            }
                            break
                        case authorizationAttributeMaxAge:
                            // not used now
                            break
                    }
                }

                if (challengeBlob === undefined) { continue }

                console.log("challenge #")
                console.log("challengeBlob", challengeBlob)
                console.log("tokenKeyEnc", tokenKeyEnc)

                // Determine type of token
                const type = (challengeBlob[0] << 8) | challengeBlob[1]
                console.log("type", type)
                const attester = "attester.example"
                const params: Params = {
                    attester,
                    challengeBlob: challengeBlob.toString(),
                    tokenKeyEnc: tokenKeyEnc?.toString()
                }
                console.log("params", params)

                // Store token in a TokenStore
                switch (type) {
                    case rateLimitedTokenType:
                        // token = fetchRateLimitedToken(clientOriginSecret, id, origin, params)
                        // tokenStore.push(token)
                        break
                    case basicPublicTokenType:
                        const token = fetchBasicToken(params)
                        TokenStore.push(token)
                        break
                }
            }

            // This request will be retired (i.e., it will be redirected to
            // the same url), thus the OnBeforeSendHeaders handler will include
            // a token in the request headers.
            return { redirectUrl: details.url }
        }
    },
    { urls: ['<all_urls>'] }, ['responseHeaders', 'blocking']
);

chrome.webRequest.onBeforeSendHeaders.addListener(
    (details: chrome.webRequest.WebRequestHeadersDetails): chrome.webRequest.BlockingResponse | void => {
        // there are no tokens
        if (TokenStore.length === 0) { return }

        const token = TokenStore.pop()
        const encodedToken = Buffer.from(token.serialize()).toString('base64')
        const headerWithToken = {
            name: "Authorization",
            value: privateTokenType + " token=" + encodedToken
        };

        let headers = new Array()
        headers = headers.concat(details.requestHeaders);
        headers.push(headerWithToken)

        return {
            requestHeaders: headers
        }
    },
    { urls: ['<all_urls>'] },
    ['requestHeaders', 'blocking', 'extraHeaders']
);

export { }
