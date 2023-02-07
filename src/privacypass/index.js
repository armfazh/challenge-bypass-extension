import { fetchPublicVerifToken } from './pubVerifToken.ts';
import { parseWWWAuthHeader } from './httpAuthScheme.ts';
import { uint8ToB64URL } from './util.ts';

const BasicPublicTokenType = 0x0002;
const RateLimitedTokenType = 0x0003;

chrome.declarativeNetRequest.getDynamicRules().then((r) => console.log('rules dyn:', r));
chrome.declarativeNetRequest.getSessionRules().then((r) => console.log('rules ses:', r));

chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('start the installation', details);

    chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[1423]})

    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
        console.log(`paso por debug:
        rulesetId:      ${info.rule.rulesetId},
        ruleId:         ${info.rule.ruleId},
        frameId:        ${info.request.frameId},
        initiator:      ${info.request.initiator},
        method:         ${info.request.method},
        partentFrameId: ${info.request.partentFrameId},
        requestId:      ${info.request.requestId},
        tabId:          ${info.request.tabId},
        type:           ${info.request.type},
        url:            ${info.request.url},
        `);
    });
});

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        console.log('onBfeReq', details.requestId);
        console.log('onBfeReq', details.url);
    },
    { urls: ['<all_urls>'] },
    ['extraHeaders'],
);

async function header_to_token(details, header) {

    const tokenDetails = parseWWWAuthHeader(header);
    if (tokenDetails.length === 0) { return; }

    console.log('new token details for: ', details.requestId);
    const td = tokenDetails[0];
    switch (td.type) {
        case BasicPublicTokenType:
            console.log(`type of challenge: ${td.type} is supported`);
            const token = await fetchPublicVerifToken(td)
            const encodedToken = uint8ToB64URL(token.serialize());
            console.log('creo token for: ', details.requestId, encodedToken);
            return encodedToken;

        case RateLimitedTokenType:
            console.log(`type of challenge: ${td.type} is not supported yet.`);
            break;
        default:
            console.log(`unrecognized type of challenge: ${td.type}`);
    }
    return null
}

chrome.webRequest.onBeforeSendHeaders.addListener(
    async (details) => {
        console.log('onBfeSendHdr', details.requestId);
        console.log('onBfeSendHdr', details.url);
        console.log('onBfeSendHdr', details.requestHeaders);

        const key = details.requestId.toString();
        const x = await chrome.storage.local.get([key]);
        console.log(`onBfeSendHdr (get) reqId: ${details.requestId} value ${x[key]}`);
        if(!x){
            return;
        }
        if(!x[key]){
            return;
        }
        if(x[key].reqId !== details.requestId){
            return;
        }

        const privateTokenChl = x[key].hdr;
        console.log('onBfeSendHdr reqId:', x[key].reqId);
        const w3HeaderValue = await header_to_token(details, privateTokenChl);
        if (w3HeaderValue === null){
            return;
        }

        console.log('onBfeSendHdr privateTokenChl:', privateTokenChl);
        console.log('onBfeSendHdr w3HeaderValue:', w3HeaderValue);

        // Add a rule to declarativeNetRequest here
        // if you want to block or modify a header from
        // this request. The change is applied after finished
        // this method, and changes can be observed in
        // onSendHeaders method.
        //
        chrome.declarativeNetRequest.updateSessionRules(
            {
                removeRuleIds: [1423],
                addRules: [
                    {
                        id: 1423,
                        priority: 1,
                        action: {
                            type: 'modifyHeaders',
                            // redirect: { url: 'https://example.com' },
                            responseHeaders: [
                                {
                                    header: 'authorization',
                                    operation: 'append',
                                    value: 'PrivateToken token=' + w3HeaderValue,
                                },
                            ],
                        },
                        // action: { type: 'block' },
                        condition: { resourceTypes: ['main_frame'] },
                    },
                ],
            },
            () => {
                console.log('The rule onBfeSendHdr was succesfully applied');
            },
        );
    },
    { urls: ['<all_urls>'] },
    ['extraHeaders', 'requestHeaders'],
);

chrome.webRequest.onSendHeaders.addListener(
    (details) => {
        console.log('onSendHdr', details.requestId);
        console.log('onSendHdr', details.url);
        console.log('onSendHdr', details.requestHeaders);
    },
    { urls: ['<all_urls>'] },
    ['extraHeaders', 'requestHeaders'],
);

chrome.webRequest.onHeadersReceived.addListener(
    async (details) => {
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
        const key = details.requestId.toString();
        const value = {
          reqId: details.requestId,
          hdr: hdr.value,
        };

        await chrome.storage.local.set({ [key]: value });
        console.log(`onHdrRcv (set) reqId: ${details.requestId} key: ${key} value: ${value}`);

        // Add a rule to declarativeNetRequest here
        // if you want to block or modify a header from
        // this request. The change is applied after finished
        // this method, and changes can be observed in
        // ResponseStarted method.
        //
        // chrome.declarativeNetRequest.updateSessionRules(
        //     {
        //         removeRuleIds: [1423],
        //         addRules: [
        //             {
        //                 id: 1423,
        //                 priority: 1,
        //                 // action: { type: 'block' },
        //                 action: {
        //                     type: 'modifyHeaders',
        //                     // redirect: { url: 'example.com' },
        //                     requestHeaders: [
        //                         {
        //                             header: 'authorization',
        //                             operation: 'set',
        //                             value: "some value here",
        //                         },
        //                     ],
        //                 },
        //                 condition: { resourceTypes: ['main_frame'] },
        //             },
        //         ],
        //     },
        //     () => {
        //         console.log('The rule onHdrRcv was succesfully applied');
        //     },
        // );

        // For some reason, doesn't send to redirect here.
        return { redirectUrl: details.url }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders'],
);

chrome.webRequest.onBeforeRedirect.addListener(
    (details) => {
        console.log('onBfeRed', details.requestId);
        console.log('onBfeRed', details.url);
        console.log('onBfeRed', details.responseHeaders);
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders'],
);

chrome.webRequest.onResponseStarted.addListener(
    (details) => {
        console.log('onRspStd', details.requestId);
        console.log('onRspStd', details.url);
        console.log('onRspStd', details.responseHeaders);
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders'],
);
