import { BasicPublicTokenType, RateLimitedTokenType, fetchPublicVerifToken } from './pubVerifToken.ts';

import { parseWWWAuthHeader } from './httpAuthScheme.ts';
import { uint8ToB64URL } from './util.ts';

chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('start the installation', details);
    chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [1423] });

    // chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    //     console.log(`paso por debug:
    //     rulesetId:      ${info.rule.rulesetId},
    //     ruleId:         ${info.rule.ruleId},
    //     frameId:        ${info.request.frameId},
    //     initiator:      ${info.request.initiator},
    //     method:         ${info.request.method},
    //     partentFrameId: ${info.request.partentFrameId},
    //     requestId:      ${info.request.requestId},
    //     tabId:          ${info.request.tabId},
    //     type:           ${info.request.type},
    //     url:            ${info.request.url},
    //     `);
    // });
});

// chrome.declarativeNetRequest.getDynamicRules().then((r) => console.log('rules dyn:', r));
// chrome.declarativeNetRequest.getSessionRules().then((r) => console.log('rules ses:', r));

async function header_to_token(details, header) {
    const tokenDetails = parseWWWAuthHeader(header);
    if (tokenDetails.length === 0) {
        return;
    }

    console.log('new token details for: ', details.requestId);
    const td = tokenDetails[0];
    switch (td.type) {
        case BasicPublicTokenType:
            console.log(`type of challenge: ${td.type} is supported`);
            const token = await fetchPublicVerifToken(td);
            const encodedToken = uint8ToB64URL(token.serialize());
            console.log('creo token for: ', details.requestId, encodedToken);
            return encodedToken;

        case RateLimitedTokenType:
            console.log(`type of challenge: ${td.type} is not supported yet.`);
            break;
        default:
            console.log(`unrecognized type of challenge: ${td.type}`);
    }
    return null;
}

chrome.webRequest.onBeforeSendHeaders.addListener(
    async (details) => {
        console.log('onBfeSendHdr', details.requestId);
        console.log('onBfeSendHdr', details.url);

        const key = details.url;
        const x = await chrome.storage.local.get([key]);
        console.log(`onBfeSendHdr (get) reqId: ${details.requestId} value ${x[key]}`);
        if (!x) {
            return;
        }
        if (!x[key]) {
            return;
        }
        if (x[key].url !== details.url) {
            return;
        }

        await chrome.storage.local.remove([key]);
    },
    { urls: ['<all_urls>'] },
    [],
);

chrome.webRequest.onSendHeaders.addListener(
    (details) => {
        console.log('onSendHdr', details.requestId);
        console.log('onSendHdr', details.url);
        console.log('onSendHdr', details.requestHeaders);

        const hdr = details.requestHeaders.find((x) => x.name.toLowerCase() === 'authorization');
        if (hdr) {
            console.log('the request has a token:', hdr.value);
            // Since the request has a token, we don't need the
            // rule that adds Authorization header.
            chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [1423] });
        }
    },
    { urls: ['<all_urls>'] },
    [ 'requestHeaders'],
);

chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        console.log('onHdrRcv', details.requestId);
        let hdr = details.responseHeaders.find((x) => x.name.toLowerCase() == 'www-authenticate');
        if (!hdr) {
            return;
        }

        console.log('onHdrRcv', details.requestId);
        console.log('onHdrRcv', details.url);
        console.log('onHdrRcv', details.responseHeaders);

        if (!hdr.value) {
            return;
        }
        const key = details.url;
        const value = {
            reqId: details.requestId,
            url: details.url,
            hdr: hdr.value,
        };

        // we need to signal that one token was created for this URL
        chrome.storage.local.set({ [key]: value });

        console.log(`onHdrRcv (set) reqId: ${details.requestId} key: ${key} value: ${value}`);
        (async (privateTokenChl) => {
            const w3HeaderValue = await header_to_token(details, privateTokenChl);
            if (w3HeaderValue === null) {
                return;
            }

            console.log('onBfeSendHdr privateTokenChl:', privateTokenChl);
            console.log('onBfeSendHdr w3HeaderValue:', w3HeaderValue);

            // Add a rule to declarativeNetRequest here if you want to block
            // or modify a header from this request. The rule is registered and
            // changes are observed between the onBeforeSendHeaders and
            // onSendHeaders methods.
            chrome.declarativeNetRequest.updateSessionRules(
                {
                    removeRuleIds: [1423],
                    addRules: [
                        {
                            id: 1423,
                            priority: 1,
                            action: {
                                type: 'modifyHeaders',
                                requestHeaders: [
                                    {
                                        header: 'Authorization',
                                        operation: 'set',
                                        value: 'PrivateToken token=' + w3HeaderValue,
                                    },
                                ],
                            },
                            condition: {
                                // Note: The urlFilter must be composed of only ASCII characters.
                                urlFilter: new URL(details.url).toString(),
                                resourceTypes: ['main_frame'],
                            },
                        },
                    ],
                },
                async () => {
                    console.log('The rule onHdrRcv was succesfully applied');
                    const q = await chrome.tabs.query({ currentWindow: true, active: true });
                    chrome.tabs.update(q.id, { url: details.url });
                },
            );
        })(hdr.value).catch((e) => {
            console.log(`onHdrRcv an error: ${e}`);
        });
    },
    { urls: ['<all_urls>'] },
    [ 'responseHeaders'],
);
