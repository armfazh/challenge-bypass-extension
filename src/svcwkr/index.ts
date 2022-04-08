
chrome.webRequest.onBeforeRequest.addListener(() => { },
    { urls: ['<all_urls>'] }, ['requestBody', 'blocking',]);


chrome.webRequest.onBeforeSendHeaders.addListener(() => { },
    { urls: ['<all_urls>'] }, ['requestHeaders', 'blocking', 'extraHeaders'],
);

chrome.webRequest.onHeadersReceived.addListener(() => { },
    { urls: ['<all_urls>'] }, ['responseHeaders', 'blocking',]);

export { }
