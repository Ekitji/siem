> **Pro Tip!** Have you found a DLL with your query and you have its hash - search here in the tables to get OPENSSLDIR. Checking the version only could be wrong if the OpenSSL version is a custom build.

## My own list with DLLs, hashes and versions.

| Filename | Version | SHA1 hash| OPENSSLDIR | Application | ENGINES DIR |
|---|---|---|---|---|---|
| libcrypto-1_1-x64.dll | 1.1.1 | 3554f7e615496e4bebd30e24a3bcbe8752c1cd3b | "C:\Program Files\Common Files\SSL" | 
| libcrypto-1_1-x64.dll | 1.1.1n | 8ab148d18164ab411595d8bb2e9f2e6cea534948 | "C:\Program Files\Common Files\SSL" | PostgreSQL |
| libcrypto-1_1-x64.dll | 1.1.1w | 13423b30f73490fa93018e433f9b4c126e86c2c1 | "C:\Program Files\Common Files\SSL" | |
| libcrypto-1_1-x64.dll | 1.1.1g | a6eb12db5d4bec6820d98058541973630a090b75 | "C:\Program Files\Common Files\SSL" | |
| libcrypto-1_1-x64.dll | 1.1.1p | 585bac48084a1c40597a0f1a6c8cd8c135ea6b4a | "\apache24\conf" | Apache24 -IncB | |
| libcrypto-1_1.dll | 1.1.1w | e1e0e7884770b062b803b8396dfce08e889eadac | "C:\Program Files (x86)\Common Files\SSL" | | "\builds\3rdparty\bash-packages\.package\lib\engines-1_1" |
| libcrypto-3.dll | 3.6.1 | fbfa3765ce078f67484e19e431b34fc7373fb36a | "C:\Program Files (x86)\Common Files\SSL" | |
| libcrypto-3.dll | 3.0.15 | 12d13a0f5e34820ad419e729a4541a32be81d728 | "C:\Program Files (x86)\Common Files\SSL" | |
| libcrypto-3.dll | 3.0.16 | 8bdaf2c1cebcc019d28ebf181de6751cad608ea4 |  "C:\Program Files (x86)\Common Files\SSL" | | "\builds\3rdparty\bash-packages\.package\lib\engines-3" | 
| libcrypto-3-x64.dll | 3.0.15 | dd64e10b064efea5c6c1e01666f6c4f62c864e7a | "C:\Program Files\Common Files\SSL" | |
| libcrypto-3-x64.dll | 3.0.12 | 7b6ccb74ab9f28ed929d0e668b638b8bed375c20 | "C:\Program Files\Common Files\SSL" | |
| libcrypto-3-x64.dll | 3.0.16 | 9ec8b76179e2b746e0d0a6a8d8bf6e8f70729ede | "C:\Program Files\Common Files\SSL" | | "\builds\3rdparty\bash-packages\.package\lib\engines-3"| 8bdaf2c1cebcc019d28ebf181de6751cad608ea4 | "C:\Program Files (x86)\Common Files\SSL" | 
| libcrypto-3-x64.dll | 3.2.1 | ee6ed4b54daca2d787ad6232fd09701aafafd8b1 | "C:\Program Files\Common Files\SSL" | |
| libeay32.dll | 1.0.2p | b09bbc7f5f010ab1d750b5290cf331b372cd7fae | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2p | ad8950da5ad9a143a05ce84ddc41e0b7420079ef | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2p | fb3eebef898defba2bfd0dbc6167a9efcbe4ac8a |  | | 
| libeay32.dll | 1.0.2u | f684152c245cc708fbaf4d1c0472d783b26c5b18 | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2u | 3c9d8851721d2f1bc13a8dcb74549fa282a5a360 | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2t | 74fa885fa59fd7f5b1c71c7736566effbae86d63 |  "/usr/local/ssl" | |
| libeay32.dll | 1.0.1g | 4e5329c4321b17a54d40df6ff6d2537ebc54691b |  "/usr/local/ssl" | |
| libeay32.dll | 1.0.2ze | abb4d4b100aaa5c47ed7b16e9dcf729964b6a197 |"/builds/3rdparty/bash-packages/.package/ssl" | PNM | 
| libeay64.dll | 0.9.8o | c4157d4340118db638c615d5c8a81193bf241dd2 | "c:/vsttech\vsttech\openssl/ssl" | |


---

> **Below table built by using following github repo** https://github.com/IndySockets/OpenSSL-Binaries/tree/master

# OpenSSL Binary Scan Results

| FileName | OpenSSLVersion | SHA1 | OPENSSLDIR | ENGINESDIR | MODULESDIR | SourceZip |
|----------|----------------|------|------------|------------|------------|-----------|
| libeay32.dll | 0.9.6k | 4e953a8d529ee6bc672610c697f9fe5f5f2860f7 |  |  |  | indy_openssl096k.zip |
| libeay32.dll | 0.9.6b | a21b7aba94cfcaefa3cbe5e0140e20669459a33f |  |  |  | indy_openssl096b.zip |
| libeay32.dll | 0.9.6m | df52dd2b19572d66fb2f01a28ea67d26b1e3e909 |  |  |  | indy_OpenSSL096m.zip |
| libeay32.dll | 0.9.6 | 1ee5afc40dc923bf6343618b50b445ba048bf60d |  |  |  | indy_openssl096.zip |
| libeay32.dll | 0.9.8h | 7f13989dbbad9c4693d4cf77bb14457ae3f5c3a7 | /usr/local/ssl |  |  | openssl-0.9.8h-i386-win32.zip |
| libeay32.dll | 0.9.8e | 0969f193e9e973f1b6df77765b4e46d4180e8183 | /usr/local/ssl |  |  | openssl-0.9.8e-i386-win32.zip |
| libeay32.dll | 0.9.8j | 7d745867d7d38bdcefe2da09a2d3e1bec1f46dca | /usr/local/ssl |  |  | openssl-0.9.8j-x64_86-win64.zip |
| libeay32.dll | 0.9.8h | c91728444b9a157b3a43b1bb4d156c034647f9fd | /usr/local/ssl |  |  | openssl-0.9.8h-win32&win64.zip |
| libeay32.dll | 0.9.8j | 749eddf680a6db757b4a99f6f3ef8ae8b4e04b51 | /usr/local/ssl |  |  | openssl-0.9.8j-i386-win32.zip |
| libeay32.dll | 0.9.8i | 9722143c6f87beb3a2285ab3a612c639b4c48ba5 | /usr/local/ssl |  |  | openssl-0.9.8i-x64_86-win64.zip |
| libeay32.dll | 0.9.8i | 56c76a32a60c20c10aeb31b4323742aec7252f03 | /usr/local/ssl |  |  | openssl-0.9.8i-i386-win32.zip |
| libeay32.dll | 0.9.8k | 0ca27684c8c2e71b02e2802dc9027552bd0dee13 | /usr/local/ssl |  |  | openssl-0.9.8k-i386-win32.zip |
| libeay32.dll | 0.9.8k | 31703b014c1ecaa7140c85b7bcc537e3188cc818 | /usr/local/ssl |  |  | openssl-0.9.8k-x64_86-win64.zip |
| libeay32.dll | 0.9.8l | 4652d350cad6b6a7def0e5da9d21004fe71b724f | /usr/local/ssl |  |  | openssl-0.9.8l-i386-win32-IndyBackport.zip |
| libeay32.dll | 0.9.8m | 3626e498865c18a593cdf8ac8617c7e25934e89a | /usr/local/ssl |  |  | openssl-0.9.8m-i386-win32.zip |
| libeay32.dll | 0.9.8l | da377416d745b4cf921ce0ac6009a7bc87b9fd0c | /usr/local/ssl |  |  | openssl-0.9.8l-i386-win32.zip |
| libeay32.dll | 0.9.8l | b31264627cb4ca34b7454e55f1d6da466a50e300 | /usr/local/ssl |  |  | openssl-0.9.8l-x64_86-win64.zip |
| libeay32.dll | 0.9.8m | 8b0ce6903b0f400a3ba7ffa41e9a3b729a4d5af3 | /usr/local/ssl |  |  | openssl-0.9.8m-x64_86-win64.zip |
| libeay32.dll | 0.9.8o | 25095af8b7b0668595dda1c51e2d996840455d03 | /usr/local/ssl/fips |  |  | openssl-0.9.8o-i386-win32-fips-1.2.zip |
| libeay32.dll | 0.9.8q | 707fb285951e0758c4513c17722ff8cbdfd00665 | /usr/local/ssl |  |  | openssl-0.9.8q-i386-win32.zip |
| libeay32.dll | 0.9.8o | 7cd00e367dfd36a04ca3e1a0fa352ce81b12584b | /usr/local/ssl |  |  | openssl-0.9.8o-x64_86-win64.zip |
| libeay32.dll | 0.9.8o | 2f61c6f3176a2b01550fbfe36e8423653e7dcbd2 | /usr/local/ssl |  |  | openssl-0.9.8o-i386-win32.zip |
| libeay32.dll | 0.9.8q | 2c7053d243a6670f16bc955e660cb2ac2b4dccbd | /usr/local/ssl |  |  | openssl-0.9.8q-x64_86-win64.zip |
| libeay32.dll | 0.9.8r | 5b5db243ccf8d7849d18c5c65ad91c6a75a6b804 | /usr/local/ssl |  |  | openssl-0.9.8r-i386-win32.zip |
| libeay32.dll | 0.9.8r | d2ba061f668fbb9e57d1d3cbcf4efb119ef87a7b | /usr/local/ssl |  |  | openssl-0.9.8r-x64_86-win64-rev2.zip |
| libeay32.dll | 0.9.8r | 7db84b5706479ce14144a03828830eb855f316e9 | /usr/local/ssl |  |  | openssl-0.9.8r-x64_86-win64.zip |
| libeay32.dll | 0.9.8r | 98c348cab0f835d6cf17c3a31cd5811f86c0388b | /usr/local/ssl |  |  | openssl-0.9.8r-i386-win32-rev2.zip |
| libeay32.dll | 0.9.8t | 8250e287cc033757e0b8bcc9d4a7feb022dd4573 | /usr/local/ssl |  |  | openssl-0.9.8t-x64_86-win64.zip |
| libeay32.dll | 0.9.8w | 406fea02bfa9f0f034df342fa340fc98b21b2caf | /usr/local/ssl |  |  | openssl-0.9.8w-i386-win32.zip |
| libeay32.dll | 0.9.8t | 9991499076ef41632e388db40cd93b55ca5a9090 | /usr/local/ssl |  |  | openssl-0.9.8t-i386-win32.zip |
| libeay32.dll | 0.9.8s | 67089a8eda11cc60127e8c89560684ab09c1455a | /usr/local/ssl |  |  | openssl-0.9.8s-x64_86-win64.zip |
| libeay32.dll | 0.9.8u | a9bfe96770288833ba5c55f8576306dc281cc3c1 | /usr/local/ssl |  |  | openssl-0.9.8u-i386-win32.zip |
| libeay32.dll | 0.9.8u | 1f27c4b6aed36202314668ef4c91d0f6fa33536a | /usr/local/ssl |  |  | openssl-0.9.8u-x64_86-win64.zip |
| libeay32.dll | 0.9.8s | f0b6aff5c91cbb358a008a3bb3fb067e10a0dfa4 | /usr/local/ssl |  |  | openssl-0.9.8s-i386-win32.zip |
| libeay32.dll | 0.9.8w | f856c7582decd024a8d79bf7701df0778aab5d16 | /usr/local/ssl |  |  | openssl-0.9.8w-x64_86-win64.zip |
| libeay32.dll | 0.9.8x | 5a847c1e8b2ae6898309eb2fc935c4d53e990a4c | /usr/local/ssl |  |  | openssl-0.9.8x-x64_86-win64.zip |
| libeay32.dll | 0.9.8y | 010f041d54376169bfbf63ba37cbe43053249d62 | /usr/local/ssl |  |  | openssl-0.9.8y-i386-win32.zip |
| libeay32.dll | 0.9.8y | 7d0da9d3331602aedf023562a9c2df3f79d2e645 | /usr/local/ssl |  |  | openssl-0.9.8y-x64_86-win64.zip |
| libeay32.dll | 0.9.8z | 4435e4a6c883d7edbb779bc0eb30d0203add5f04 | /usr/local/ssl |  |  | openssl-0.9.8zb-i386-win32.zip |
| libeay32.dll | 0.9.8z | de9074bf7971cc701dd708f0a11a17bec428ca0b | /usr/local/ssl |  |  | openssl-0.9.8zc-i386-win32.zip |
| libeay32.dll | 0.9.8x | 112c916dd913326aab29e1f2fcfb54431d9e435a | /usr/local/ssl |  |  | openssl-0.9.8x-i386-win32.zip |
| libeay32.dll | 0.9.8z | 7aabf24d7b1cb738a1202f5320f74925f1742562 | /usr/local/ssl |  |  | openssl-0.9.8zb-x64_86-win64.zip |
| libeay32.dll | 0.9.8z | 15137300318df11b412d494a9d1cb07abf3a2930 | /usr/local/ssl |  |  | openssl-0.9.8zc-x64_86-win64.zip |
| libeay32.dll | 0.9.8z | ae1f6b869f3165369cfe0e9f198d65ea7d024bc1 | /usr/local/ssl |  |  | openssl-0.9.8zd-i386-win32.zip |
| libeay32.dll | 0.9.8z | b8d57cefbb364d2bff6150ef5a2e5e9a3bf73396 | /usr/local/ssl |  |  | openssl-0.9.8zd-x64_86-win64.zip |
| libeay32.dll | 0.9.8z | e694636b6c6bed5f191094e6ac72fdcd5ec7a8ae | /usr/local/ssl |  |  | openssl-0.9.8ze-i386-win32.zip |
| libeay32.dll | 0.9.8z | 0f5b92bb376f5b4fdbfb78559b8ba0f8903a5de0 | /usr/local/ssl |  |  | openssl-0.9.8ze-x64_86-win64.zip |
| libeay32.dll | 0.9.8z | d989369f2eb43acd9725888d86e01d571d2b328b | /usr/local/ssl |  |  | openssl-0.9.8zf-x64_86-win64.zip |
| libeay32.dll | 0.9.8z | 731d78b3a4478ac40a6186fd2e010acb02d6ca14 | /usr/local/ssl |  |  | openssl-0.9.8zg-x64_86-win64.zip |
| libeay32.dll | 0.9.8z | f630aa829e919ebfd6a5bd0f910c20905da38bfa | /usr/local/ssl |  |  | openssl-0.9.8zf-i386-win32.zip |
| libeay32.dll | 0.9.8z | 576edfe0e5bba4d87fdb7de9ff48e5c38a0f0778 | /usr/local/ssl |  |  | openssl-0.9.8zh-i386-win32.zip |
| libeay32.dll | 0.9.8z | e53891b29f4057780fc73848024d90f2cfe15d34 | /usr/local/ssl |  |  | openssl-0.9.8zg-i386-win32.zip |
| libeay32.dll | 0.9.8z | efda8244251180b48c38fce3a35dff5e95c56f0d | /usr/local/ssl |  |  | openssl-0.9.8zh-x64_86-win64.zip |
| libeay32.dll | 1.0.0a | accda53eeee6949d4b1f9b5a6bd7d4411bfb4c86 | /usr/local/ssl |  |  | openssl-1.0.0a-i386-win32.zip |
| libeay32.dll | 1.0.0a | f5a25b7b91884962efa889c585f9717bac66226c | /usr/local/ssl |  |  | openssl-1.0.0a-x64_86-win64.zip |
| libeay32.dll | 1.0.0 | 28e9fd9ac81b28c8b2b85102c16445e731433462 | /usr/local/ssl |  |  | openssl-1.0.0-i386-win32.zip |
| libeay32.dll | 1.0.0c | 8e002df3bd3d009da3215954348c98f49a4c5e24 | /usr/local/ssl |  |  | openssl-1.0.0c-i386-win32.zip |
| libeay32.dll | 1.0.0 | bf9772e27ce12cab5ad1ea6de27ad935a128b87a | /usr/local/ssl |  |  | openssl-1.0.0-x64_86-win64.zip |
| libeay32.dll | 1.0.0c | 734301e7fece352534d59c89c39da4199c0dea78 | /usr/local/ssl |  |  | openssl-1.0.0c-x64_86-win64.zip |
| libeay32.dll | 1.0.0d | 64aeb06f9008b42a614a5e6d63518792bf496ce4 | /usr/local/ssl |  |  | openssl-1.0.0d-i386-win32.zip |
| libeay32.dll | 1.0.0d | c8eece2bbe69bdfb64e71ed86d6e7c4f351b79c8 | /usr/local/ssl |  |  | openssl-1.0.0d-i386-win32-rev2.zip |
| libeay32.dll | 1.0.0d | f9583435c6de0a9fe12faf1efad9ee2fbe3a1273 | /usr/local/ssl |  |  | openssl-1.0.0d-x64_86-win64-rev2.zip |
| libeay32.dll | 1.0.0e | 24f4c132adf6a0809b832193537fbf7fb3c1cd87 | /usr/local/ssl |  |  | openssl-1.0.0e-i386-win32.zip |
| libeay32.dll | 1.0.0f | cc1978254dd6915968bf001d06c904f0e7a5fb89 | /usr/local/ssl |  |  | openssl-1.0.0f-i386-win32.zip |
| libeay32.dll | 1.0.0g | bb2f957df822e97f1af54b0607d8c927a4f6a9ae | /usr/local/ssl |  |  | openssl-1.0.0g-i386-win32.zip |
| libeay32.dll | 1.0.0d | 58c915daee6b2f1b6aa03754e12eaba6263f438e | /usr/local/ssl |  |  | openssl-1.0.0d-x64_86-win64.zip |
| libeay32.dll | 1.0.0f | 3d6f8f611683b8dc00366f0e599db52c6eb3f1fe | /usr/local/ssl |  |  | openssl-1.0.0f-x64_86-win64.zip |
| libeay32.dll | 1.0.0e | 6850c37522be9e46f21d790433bc3c32388fd304 | /usr/local/ssl |  |  | openssl-1.0.0e-x64_86-win64.zip |
| libeay32.dll | 1.0.0g | d168665c3861689d22f5e341fff94effe93e2c7d | /usr/local/ssl |  |  | openssl-1.0.0g-x64_86-win64.zip |
| libeay32.dll | 1.0.0h | 12a3b8f8e7b1c5fde50082731b8110983e4e8620 | /usr/local/ssl |  |  | openssl-1.0.0h-i386-win32.zip |
| libeay32.dll | 1.0.0h | 8f9537b72e2d4fe6e9ff847cd4797f36677a0a27 | /usr/local/ssl |  |  | openssl-1.0.0h-x64_86-win64.zip |
| libeay32.dll | 1.0.0i | 6a407f8e328e1336547a96cba128fd82e4549123 | /usr/local/ssl |  |  | openssl-1.0.0i-i386-win32.zip |
| libeay32.dll | 1.0.0k | 1d024275ab1ef7502f2ecd01033c6c478dfd55dd | /usr/local/ssl |  |  | openssl-1.0.0k-i386-win32.zip |
| libeay32.dll | 1.0.0j | 7c963369946a174906c8096be91ebde559819e26 | /usr/local/ssl |  |  | openssl-1.0.0j-x64_86-win64.zip |
| libeay32.dll | 1.0.0i | cfe5b4ed2f02b172a15297e6af995eefb0ffa7ef | /usr/local/ssl |  |  | openssl-1.0.0i-x64_86-win64.zip |
| libeay32.dll | 1.0.0j | 79897344e1ca12014cd95b399f30577c35cb6cee | /usr/local/ssl |  |  | openssl-1.0.0j-i386-win32.zip |
| libeay32.dll | 1.0.0k | b40d1c418f9fded5992f68f880d2004e39c9c1b3 | /usr/local/ssl |  |  | openssl-1.0.0k-x64_86-win64.zip |
| libeay32.dll | 1.0.0l | 8680ca01460a7ecb530f6f25c7b46816562ef1bc | /usr/local/ssl |  |  | openssl-1.0.0l-i386-win32.zip |
| libeay32.dll | 1.0.0n | aa6d6987d1bba7ed29416f32c8d0a3658e8f7beb | /usr/local/ssl |  |  | openssl-1.0.0n-i386-win32.zip |
| libeay32.dll | 1.0.0l | 3e443e50e1b0a999e35d06377eed4ebad4946b99 | /usr/local/ssl |  |  | openssl-1.0.0l-x64_86-win64.zip |
| libeay32.dll | 1.0.0o | 90cd627f6eba3abc164d7bbf41851ec1332110c4 | /usr/local/ssl |  |  | openssl-1.0.0o-i386-win32.zip |
| libeay32.dll | 1.0.0n | 2a621a5f5fb6b3487b33f3f780126bf046d7ac12 | /usr/local/ssl |  |  | openssl-1.0.0n-x64_86-win64.zip |
| libeay32.dll | 1.0.0q | 5a0dba92c709c85137bef7035314c2e942c90d0f | /usr/local/ssl |  |  | openssl-1.0.0q-i386-win32.zip |
| libeay32.dll | 1.0.0p | ac3aa51dace8ddb59365d35ae2786c1cc331d4f4 | /usr/local/ssl |  |  | openssl-1.0.0p-i386-win32.zip |
| libeay32.dll | 1.0.0r | fb873acc4bb297c2632649d6842cacc996f300d6 | /usr/local/ssl |  |  | openssl-1.0.0r-i386-win32.zip |
| libeay32.dll | 1.0.0o | 01b34300aa069f8e04584d6eb2413b91c8975c30 | /usr/local/ssl |  |  | openssl-1.0.0o-x64_86-win64.zip |
| libeay32.dll | 1.0.0p | fa8e2ee7f1357ff00983e9098f8e5d938a9ed667 | /usr/local/ssl |  |  | openssl-1.0.0p-x64_86-win64.zip |
| libeay32.dll | 1.0.0q | 94f9d90a6efc5d763f0e76ed03f247ee1d4bbf65 | /usr/local/ssl |  |  | openssl-1.0.0q-x64_86-win64.zip |
| libeay32.dll | 1.0.0s | 6625c81d03440d3ee8ec186c3d8e16daa137300a | /usr/local/ssl |  |  | openssl-1.0.0s-i386-win32.zip |
| libeay32.dll | 1.0.0r | 6715ef19ed3bbea1c824914444a36f7a0dc74b70 | /usr/local/ssl |  |  | openssl-1.0.0r-x64_86-win64.zip |
| libeay32.dll | 1.0.0t | 56f76eae1ef9550d9e81c6e7ec5b0306d43d45df | /usr/local/ssl |  |  | openssl-1.0.0t-i386-win32.zip |
| libeay32.dll | 1.0.0s | 55fd906663b486318f47982f5c4f5d9f822e2173 | /usr/local/ssl |  |  | openssl-1.0.0s-x64_86-win64.zip |
| libeay32.dll | 1.0.1 | 7e68a9501e627cb1b1bf03bc67c721c60645acd1 | /usr/local/ssl |  |  | openssl-1.0.1-i386-win32.zip |
| libeay32.dll | 1.0.1c | e97422ef6b23366fcd196df334bd111febf2e880 | /usr/local/ssl |  |  | openssl-1.0.1c-i386-win32.zip |
| libeay32.dll | 1.0.0t | 442a4572973f80f2acafaf80422b24e1ba40afc6 | /usr/local/ssl |  |  | openssl-1.0.0t-x64_86-win64.zip |
| libeay32.dll | 1.0.1b | 81b534f6d130ee55fb3c99d04a22c7b033973760 | /usr/local/ssl |  |  | openssl-1.0.1b-i386-win32.zip |
| libeay32.dll | 1.0.1b | d5ed9714e92f65d4915a2a72247fb8d60ee16eb3 | /usr/local/ssl |  |  | openssl-1.0.1b-x64_86-win64.zip |
| libeay32.dll | 1.0.1 | 511bd013f0734f478b719f82a958d62e9b4f1ce9 | /usr/local/ssl |  |  | openssl-1.0.1-x64_86-win64.zip |
| libeay32.dll | 1.0.1c | 0e8729a0bd035a47855f85fe77213642acbd4038 | /usr/local/ssl |  |  | openssl-1.0.1c-x64_86-win64.zip |
| libeay32.dll | 1.0.1e | 1e9ee2eafeae2cfcfb4e7153231e4c89a26fa1ce | /usr/local/ssl |  |  | openssl-1.0.1e-i386-win32.zip |
| libeay32.dll | 1.0.1e | 51bf011de9087b53a6f8b31cf267cc130d66c966 | /usr/local/ssl |  |  | openssl-1.0.1e-x64_86-win64.zip |
| libeay32.dll | 1.0.1f | b5a4d3604dc679ce319d0c66db97fccbc3a42da9 | /usr/local/ssl |  |  | openssl-1.0.1f-i386-win32.zip |
| libeay32.dll | 1.0.1g | 1676a23f97b4a620a733e64b6cc5da4a902e3360 | /usr/local/ssl |  |  | openssl-1.0.1g-i386-win32.zip |
| libeay32.dll | 1.0.1h | 3fe3b581c67a210dbbcf62c6f79388637f8c0518 | /usr/local/ssl |  |  | openssl-1.0.1h-i386-win32.zip |
| libeay32.dll | 1.0.1f | 544cf8ba1c9f3f870d771cd78252623c690407a6 | /usr/local/ssl |  |  | openssl-1.0.1f-x64_86-win64.zip |
| libeay32.dll | 1.0.1i | 16440daa18327e70c133ed10155d3c13e49cc793 | /usr/local/ssl |  |  | openssl-1.0.1i-x64_86-win64.zip |
| libeay32.dll | 1.0.1i | a825295347e31eaa2ae27c7ad2ec20fed0e75b3d | /usr/local/ssl |  |  | openssl-1.0.1i-i386-win32.zip |
| libeay32.dll | 1.0.1g | fe9f300dd562486bd82a406b3e76c104c18d47b0 | /usr/local/ssl |  |  | openssl-1.0.1g-x64_86-win64.zip |
| libeay32.dll | 1.0.1h | e46c259fcd4331355ce84cceb548b52a3f7df0ac | /usr/local/ssl |  |  | openssl-1.0.1h-x64_86-win64.zip |
| libeay32.dll | 1.0.1j | bd031b175bfdd2b01ce0245a7ab08628abdacb4c | /usr/local/ssl |  |  | openssl-1.0.1j-i386-win32.zip |
| libeay32.dll | 1.0.1k | 8ff232a1694cbc0af78eca71ff86ce89a3c69fdb | /usr/local/ssl |  |  | openssl-1.0.1k-x64_86-win64.zip |
| libeay32.dll | 1.0.1k | 89c4065a2b4dcf13f46aef59c1e92ec29b296e70 | /usr/local/ssl |  |  | openssl-1.0.1k-i386-win32.zip |
| libeay32.dll | 1.0.1j | fb5b7b6a5fa1756effdd551e14b684824728842d | /usr/local/ssl |  |  | openssl-1.0.1j-x64_86-win64.zip |
| libeay32.dll | 1.0.1l | ceec613ebfa4415ba9127587f0e7707790950a35 | /usr/local/ssl |  |  | openssl-1.0.1l-i386-win32.zip |
| libeay32.dll | 1.0.1m | 10d867188e457e64256fd80a6b716f80cd2572a8 | /usr/local/ssl |  |  | openssl-1.0.1m-i386-win32.zip |
| libeay32.dll | 1.0.1l | 4c40e10274f9db918d662bdfc8590e1d5446519f | /usr/local/ssl |  |  | openssl-1.0.1l-x64_86-win64.zip |
| libeay32.dll | 1.0.1o | 4349cbf3ab8f4d51d5e650bfa83f6cc6bff5016b | /usr/local/ssl |  |  | openssl-1.0.1o-i386-win32.zip |
| libeay32.dll | 1.0.1m | 8d7c2c5022588b03f2650cf3ba724b29d105bdde | /usr/local/ssl |  |  | openssl-1.0.1m-x64_86-win64.zip |
| libeay32.dll | 1.0.1p | 35ec8a16d94db0864d8b11458d7ec06312465cce | /usr/local/ssl |  |  | openssl-1.0.1p-i386-win32.zip |
| libeay32.dll | 1.0.1o | 0d518325a3ac6116166f31131219428286c57a77 | /usr/local/ssl |  |  | openssl-1.0.1o-x64_86-win64.zip |
| libeay32.dll | 1.0.1p | 555b46b4a3973557c1c375472f33ed28e4e24a6a | /usr/local/ssl |  |  | openssl-1.0.1p-x64_86-win64.zip |
| libeay32.dll | 1.0.1q | 23dc143f64e24d34314ba40a67cdb83e6b07bfce | /usr/local/ssl |  |  | openssl-1.0.1q-x64_86-win64.zip |
| libeay32.dll | 1.0.1q | a207b81382064fd94b5bdaa5a7956fe7d429be23 | /usr/local/ssl |  |  | openssl-1.0.1q-i386-win32.zip |
| libeay32.dll | 1.0.1r | 35e6d3e8038a073690f798bb828c12a6e1ced8f0 | /usr/local/ssl |  |  | openssl-1.0.1r-i386-win32.zip |
| libeay32.dll | 1.0.1s | 3ff8b03e165cedc9d87edbac8b137d389e5d699a | /usr/local/ssl |  |  | openssl-1.0.1s-i386-win32.zip |
| libeay32.dll | 1.0.1r | 647964ce5873f29ee50fcc94754449981d7d1226 | /usr/local/ssl |  |  | openssl-1.0.1r-x64_86-win64.zip |
| libeay32.dll | 1.0.1s | bf208b66d0966f378bf7814b335962bf803091dd | /usr/local/ssl |  |  | openssl-1.0.1s-x64_86-win64.zip |
| libeay32.dll | 1.0.1t | a229ba125c98082d4ed530051418d2a584be0d62 | /usr/local/ssl |  |  | openssl-1.0.1t-i386-win32.zip |
| libeay32.dll | 1.0.1t | 88a58362593edcc35fc12a23f60f95fdf3f3bc0c | /usr/local/ssl |  |  | openssl-1.0.1t-x64_86-win64.zip |
| libeay32.dll | 1.0.1u | bdbb3f3464698bf0d3ff60ca192592b23352fdaf | /usr/local/ssl |  |  | openssl-1.0.1u-i386-win32.zip |
| libeay32.dll | 1.0.2 | 22c9aee60cf0286f22690cf2d8cbf1cdb1f6e394 | /usr/local/ssl |  |  | openssl-1.0.2-i386-win32.zip |
| libeay32.dll | 1.0.1u | 0a7f72c56db1ba2d769a292bbca176b61aaafe14 | /usr/local/ssl |  |  | openssl-1.0.1u-x64_86-win64.zip |
| libeay32.dll | 1.0.2a | 84fe64c29404e73eb03a950fdc2a0b6314f05b32 | /usr/local/ssl |  |  | openssl-1.0.2a-i386-win32.zip |
| libeay32.dll | 1.0.2a | 2cf5db76a32190f7fe97efc4285419cab638c43b | /usr/local/ssl |  |  | openssl-1.0.2a-x64_86-win64.zip |
| libeay32.dll | 1.0.2 | f12d2ca58bff5813a255110a27d3eb432ad211e8 | /usr/local/ssl |  |  | openssl-1.0.2-x64_86-win64.zip |
| libeay32.dll | 1.0.2c | c6382c38a48231d73985183b4cdfc034c621ad4e | /usr/local/ssl |  |  | openssl-1.0.2c-i386-win32.zip |
| libeay32.dll | 1.0.2e | 21fc38157ac375741709147ffa9cde4ee19ed737 | /usr/local/ssl |  |  | openssl-1.0.2e-i386-win32.zip |
| libeay32.dll | 1.0.2c | deea6a8c64ac5b878b7e0017baff011a9880c6fe | /usr/local/ssl |  |  | openssl-1.0.2c-x64_86-win64.zip |
| libeay32.dll | 1.0.2d | abe57f749650fdebbaa6792e3676294c20db6abe | /usr/local/ssl |  |  | openssl-1.0.2d-i386-win32.zip |
| libeay32.dll | 1.0.2d | a24a8310c9be2c477ac3a536eccf76d72a230d99 | /usr/local/ssl |  |  | openssl-1.0.2d-x64_86-win64.zip |
| libeay32.dll | 1.0.2f | 5b42790b3519a93dbaba97cc5efaaf96fdc74294 | /usr/local/ssl |  |  | openssl-1.0.2f-i386-win32.zip |
| libeay32.dll | 1.0.2f | 30f2fa6d93ce0a7429ea89657b02e25cdb4dfe5a | /usr/local/ssl |  |  | openssl-1.0.2f-x64_86-win64.zip |
| libeay32.dll | 1.0.2g | 5a0f33c471005f71aa05967e2fcf04c9fbb2c0d2 | /usr/local/ssl |  |  | openssl-1.0.2g-i386-win32.zip |
| libeay32.dll | 1.0.2h | 5a138f31b36fa689f783bb1325a34566fa725865 | /usr/local/ssl |  |  | openssl-1.0.2h-i386-win32.zip |
| libeay32.dll | 1.0.2i | b9beed7d7e8ce7d848f780bb5e69a74c9c4482d7 | /usr/local/ssl |  |  | openssl-1.0.2i-i386-win32.zip |
| libeay32.dll | 1.0.2e | ce3841a3a14c6201c7f391787e40b68b1607c0c8 | /usr/local/ssl |  |  | openssl-1.0.2e-x64_86-win64.zip |
| libeay32.dll | 1.0.2h | 247fad7f3ff9a5eb7ee328c8f930e40aa26f2bf2 | /usr/local/ssl |  |  | openssl-1.0.2h-x64_86-win64.zip |
| libeay32.dll | 1.0.2i | 3a394bec5dbe70c75d7e154e72c7883ec0a33976 | /usr/local/ssl |  |  | openssl-1.0.2i-x64_86-win64.zip |
| libeay32.dll | 1.0.2j | be25d0575530aab50b0bb96571ea52124bdaaf77 | /usr/local/ssl |  |  | openssl-1.0.2j-i386-win32.zip |
| libeay32.dll | 1.0.2g | f6fd2f79bd6900a020b7092e5189d6e1e085495e | /usr/local/ssl |  |  | openssl-1.0.2g-x64_86-win64.zip |
| libeay32.dll | 1.0.2j | 58f3cc096cfc002f575fb9041de757da8af6fd8d | /usr/local/ssl |  |  | openssl-1.0.2j-x64_86-win64.zip |
| libeay32.dll | 1.0.2k | f521d8063ac8194b870fb5f0dfdf77f285c910d3 | /usr/local/ssl |  |  | openssl-1.0.2k-i386-win32.zip |
| libeay32.dll | 1.0.2n | 0ba8fda273f2fd9900a6ddd926d7630c732d5aaa | /usr/local/ssl |  |  | openssl-1.0.2n-i386-win32.zip |
| libeay32.dll | 1.0.2m | 21e4d9d6a09d24d1bb2da3d035bffb8e357a163d | /usr/local/ssl |  |  | openssl-1.0.2m-i386-win32.zip |
| libeay32.dll | 1.0.2l | a9b03df81acdabbc51639a4e2d4c7169a9fb2f25 | /usr/local/ssl |  |  | openssl-1.0.2l-x64_86-win64.zip |
| libeay32.dll | 1.0.2k | d34a0ba0dd7b3b1f900a7e02772e197e974b4a73 | /usr/local/ssl |  |  | openssl-1.0.2k-x64_86-win64.zip |
| libeay32.dll | 1.0.2m | fd065967d9a94fdb8343db74e706131f807f53ab | /usr/local/ssl |  |  | openssl-1.0.2m-x64_86-win64.zip |
| libeay32.dll | 1.0.2l | ba59b7df027bfc04f3add8c08bc408a927acc32a | /usr/local/ssl |  |  | openssl-1.0.2l-i386-win32.zip |
| libeay32.dll | 1.0.2n | c4949c398e9b5a878634d07c19b92c2ee557241a | /usr/local/ssl |  |  | openssl-1.0.2n-x64_86-win64.zip |
| libeay32.dll | 1.0.2o | 7181fffaa6b8f0f29cf7cdd1b1b859c2b956d399 | /usr/local/ssl |  |  | openssl-1.0.2o-i386-win32.zip |
| libeay32.dll | 1.0.2p | b09bbc7f5f010ab1d750b5290cf331b372cd7fae | /usr/local/ssl |  |  | openssl-1.0.2p-i386-win32.zip |
| libeay32.dll | 1.0.2o | 35e165f9469f1d8c97f0936201658e54405f51d1 | /usr/local/ssl |  |  | openssl-1.0.2o-x32-VC2017.zip |
| libeay32.dll | 1.0.2o | 9876f8bd03fcc83dec2a367755843b6e14112c51 | /usr/local/ssl |  |  | openssl-1.0.2o-x64_86-win64.zip |
| libeay32.dll | 1.0.2p | ad8950da5ad9a143a05ce84ddc41e0b7420079ef | /usr/local/ssl |  |  | openssl-1.0.2p-x64_86-win64.zip |
| libeay32.dll | 1.0.2q | 3e27b636863fefd991c57e8f4657aded333292e1 | /usr/local/ssl |  |  | openssl-1.0.2q-i386-win32.zip |
| libeay32.dll | 1.0.2q | 2cb7253f73a30453144574c2258192f0affecfe4 | /usr/local/ssl |  |  | openssl-1.0.2q-x64_86-win64.zip |
| libeay32.dll | 1.0.2o | c06cf5031fbb661a25acd326b666d66404b0e7f7 | /usr/local/ssl |  |  | openssl-1.0.2o-x64-VC2017.zip |
| libeay32.dll | 1.0.2r | 1403c2eea8f16b0c37062c649a146025243139ab | /usr/local/ssl |  |  | openssl-1.0.2r-i386-win32.zip |
| libeay32.dll | 1.0.2t | bd0806e27bbb7b53d88165760ec35e91c1aa512d | /usr/local/ssl |  |  | openssl-1.0.2t-i386-win32.zip |
| libeay32.dll | 1.0.2s | 2802cc6e3b2ddc42c130e943f43970c3ef959c21 | /usr/local/ssl |  |  | openssl-1.0.2s-i386-win32.zip |
| libeay32.dll | 1.0.2r | ef9697aca0a51387bda22202ac464701f8405bad | /usr/local/ssl |  |  | openssl-1.0.2r-x64_86-win64.zip |
| libeay32.dll | 1.0.2u | f684152c245cc708fbaf4d1c0472d783b26c5b18 | /usr/local/ssl |  |  | openssl-1.0.2u-i386-win32.zip |
| libeay32.dll | 1.0.2s | 0b06d56e514429d4b0f0959d9283d50e9a2bf0f0 | /usr/local/ssl |  |  | openssl-1.0.2s-x64_86-win64.zip |
| libeay32.dll | 1.0.2u | 3c9d8851721d2f1bc13a8dcb74549fa282a5a360 | /usr/local/ssl |  |  | openssl-1.0.2u-x64_86-win64.zip |
| libeay32.dll | 1.0.2t | 5ebbb62acfebab6d109bae51fd247eb36f703ddd | /usr/local/ssl |  |  | openssl-1.0.2t-x64_86-win64.zip |
| libcrypto-1_1.dll | 1.1.0h | 6ba25536f78f5023fd64209b9569aea653261841 | C:\Program Files (x86)\Common Files\SSL | C:\Program Files (x86)\OpenSSL\lib\engines-1_1 |  | openssl-1.1.0h-x32-VC2017.zip |
| libcrypto-1_1-x64.dll | 1.1.0h | 8b57cf31840a76830cdff1d6e580b0ea30659aaf | C:\Program Files\Common Files\SSL | C:\Program Files\OpenSSL\lib\engines-1_1 |  | openssl-1.1.0h-x64-VC2017.zip |
| libcrypto-3-x64.dll | 3.0.14 | cd65846a2889938d6bd793a2e28601149690fe2b | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.0.14-win64.zip |
| libcrypto-3-x64.dll | 3.0.15 | fd336da5a09a15f8b0e5df77c615258b76bb3bc1 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.0.15-win64.zip |
| libcrypto-3.dll | 3.0.15 | 93aff7fbecce16615d59b50269b0431cf97bf23b | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.0.15-win32.zip |
| libcrypto-3.dll | 3.0.14 | 615db0706b9330bb1384fb00749798c18a4dc185 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.0.14-win32.zip |
| libcrypto-3.dll | 3.1.6 | 68da22b298b8f1beb3d85b063c68ed8bba79e142 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.1.6-win32.zip |
| libcrypto-3.dll | 3.1.7 | c99ba9dbd301558df38ac9a86b6ec508de1857ad | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.1.7-win32.zip |
| libcrypto-3-x64.dll | 3.1.6 | 9d753412b59d71fd71d7cbbb4a8f1ed4e60ea5ab | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.1.6-win64.zip |
| libcrypto-3.dll | 3.2.2 | bf70e226bcbafd5f810ccf84d554ba1c596efda9 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.2.2-win32.zip |
| libcrypto-3-x64.dll | 3.1.7 | 5745c979db1709458b8fb663bad58e58535b0db5 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.1.7-win64.zip |
| libcrypto-3.dll | 3.3.1 | a25af4b700e07c0b7f8a0b12cf39ce38a6010365 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.3.1-win32.zip |
| libcrypto-3.dll | 3.2.3 | 5ef15166ddc49071f8856f4c343e8c7d85cf7fab | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.2.3-win32.zip |
| libcrypto-3-x64.dll | 3.2.3 | c0e8d908db7d640794827cb99e6f0ac7f15b6e84 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.2.3-win64.zip |
| libcrypto-3-x64.dll | 3.2.2 | f96428f4c26a9e870a1553df459eae44db7ffed3 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.2.2-win64.zip |
| libcrypto-3.dll | 3.3.2 | 124be9942b50ce9be9d7ac4f5522da510b596fd1 | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib/engines-3 | C:/msys64/usr/local/lib/ossl-modules | openssl-3.3.2-win32.zip |
| libcrypto-3-x64.dll | 3.3.1 | 2713ae0fb264aeecc715cf1963df8e4bc78e3e8e | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.3.1-win64.zip |
| libcrypto-3-x64.dll | 3.3.2 | ffe6e6ca9ef222967c5439dfac8d7110703af7ac | C:/msys64/usr/local/ssl | C:/msys64/usr/local/lib64/engines-3 | C:/msys64/usr/local/lib64/ossl-modules | openssl-3.3.2-win64.zip |

---
## Summary

| Metric | Value |
|--------|-------|
| ZIPs scanned       | 197 |
| ZIPs with DLLs     | 193 |
| Unique DLLs found  | 193 |
| Duplicates skipped | 7 |
| OpenSSL versions   | 0.9.6, 0.9.6b, 0.9.6k, 0.9.6m, 0.9.8e, 0.9.8h, 0.9.8i, 0.9.8j, 0.9.8k, 0.9.8l, 0.9.8m, 0.9.8o, 0.9.8q, 0.9.8r, 0.9.8s, 0.9.8t, 0.9.8u, 0.9.8w, 0.9.8x, 0.9.8y, 0.9.8z, 1.0.0, 1.0.0a, 1.0.0c, 1.0.0d, 1.0.0e, 1.0.0f, 1.0.0g, 1.0.0h, 1.0.0i, 1.0.0j, 1.0.0k, 1.0.0l, 1.0.0n, 1.0.0o, 1.0.0p, 1.0.0q, 1.0.0r, 1.0.0s, 1.0.0t, 1.0.1, 1.0.1b, 1.0.1c, 1.0.1e, 1.0.1f, 1.0.1g, 1.0.1h, 1.0.1i, 1.0.1j, 1.0.1k, 1.0.1l, 1.0.1m, 1.0.1o, 1.0.1p, 1.0.1q, 1.0.1r, 1.0.1s, 1.0.1t, 1.0.1u, 1.0.2, 1.0.2a, 1.0.2c, 1.0.2d, 1.0.2e, 1.0.2f, 1.0.2g, 1.0.2h, 1.0.2i, 1.0.2j, 1.0.2k, 1.0.2l, 1.0.2m, 1.0.2n, 1.0.2o, 1.0.2p, 1.0.2q, 1.0.2r, 1.0.2s, 1.0.2t, 1.0.2u, 1.1.0h, 3.0.14, 3.0.15, 3.1.6, 3.1.7, 3.2.2, 3.2.3, 3.3.1, 3.3.2 |
| Generated          | 2026-03-24 21:53:21 |
