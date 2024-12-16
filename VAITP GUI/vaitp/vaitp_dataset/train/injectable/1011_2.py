[
    {
        "action": "add",
        "when": "29cb20bd563c02671b31dd840139e93dd37150a1",
        "short": "[priority] **A new release type has been added!**\n    * [`nightly`](https://github.com/yt-dlp/yt-dlp/releases/tag/nightly) builds will be made after each push, containing the latest fixes (but also possibly bugs).\n    * When using `--update`/`-U`, a release binary will only update to its current channel (either `stable` or `nightly`).\n    * The `--update-to` option has been added allowing the user more control over program upgrades (or downgrades).\n    * `--update-to` can change the release channel (`stable`, `nightly`) and also upgrade or downgrade to specific tags.\n    * **Usage**: `--update-to CHANNEL`, `--update-to TAG`, `--update-to CHANNEL@TAG`"
    },
    {
        "action": "add",
        "when": "5038f6d713303e0967d002216e7a88652401c22a",
        "short": "[priority] **YouTube throttling fixes!**"
    },
    {
        "action": "remove",
        "when": "2e023649ea4e11151545a34dc1360c114981a236"
    },
    {
        "action": "add",
        "when": "01aba2519a0884ef17d5f85608dbd2a455577147",
        "short": "[priority] YouTube: Improved throttling and signature fixes"
    },
    {
        "action": "change",
        "when": "c86e433c35fe5da6cb29f3539eef97497f84ed38",
        "short": "[extractor/niconico:series] Fix extraction (#6898)",
        "authors": ["sqrtNOT"]
    },
    {
        "action": "change",
        "when": "69a40e4a7f6caa5662527ebd2f3c4e8aa02857a2",
        "short": "[extractor/youtube:music_search_url] Extract title (#7102)",
        "authors": ["kangalio"]
    },
    {
        "action": "change",
        "when": "8417f26b8a819cd7ffcd4e000ca3e45033e670fb",
        "short": "Add option `--color` (#6904)",
        "authors": ["Grub4K"]
    },
    {
        "action": "change",
        "when": "b4e0d75848e9447cee2cd3646ce54d4744a7ff56",
        "short": "Improve `--download-sections`\n    - Support negative time-ranges\n    - Add `*from-url` to obey time-ranges in URL",
        "authors": ["pukkandan"]
    },
    {
        "action": "change",
        "when": "1e75d97db21152acc764b30a688e516f04b8a142",
        "short": "[extractor/youtube] Add `ios` to default clients used\n        - IOS is affected neither by 403 nor by nsig so helps mitigate them preemptively\n        - IOS also has higher bit-rate 'premium' formats though they are not labeled as such",
        "authors": ["pukkandan"]
    },
    {
        "action": "change",
        "when": "f2ff0f6f1914b82d4a51681a72cc0828115dcb4a",
        "short": "[extractor/motherless] Add gallery support, fix groups (#7211)",
        "authors": ["rexlambert22", "Ti4eeT4e"]
    },
    {
        "action": "change",
        "when": "a4486bfc1dc7057efca9dd3fe70d7fa25c56f700",
        "short": "[misc] Revert \"Add automatic duplicate issue detection\"",
        "authors": ["pukkandan"]
    },
    {
        "action": "add",
        "when": "1ceb657bdd254ad961489e5060f2ccc7d556b729",
        "short": "[priority] Security: [[CVE-2023-35934](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35934)] Fix [Cookie leak](https://github.com/yt-dlp/yt-dlp/security/advisories/GHSA-v8mc-9377-rwjj)\n    - `--add-header Cookie:` is deprecated and auto-scoped to input URL domains\n    - Cookies are scoped when passed to external downloaders\n    - Add `cookies` field to info.json and deprecate `http_headers.Cookie`"
    },
    {
        "action": "change",
        "when": "b03fa7834579a01cc5fba48c0e73488a16683d48",
        "short": "[ie/twitter] Revert 92315c03774cfabb3a921884326beb4b981f786b",
        "authors": ["pukkandan"]
    },
    {
        "action": "change",
        "when": "fcd6a76adc49d5cd8783985c7ce35384b72e545f",
        "short": "[test] Add tests for socks proxies (#7908)",
        "authors": ["coletdjnz"]
    },
    {
        "action": "change",
        "when": "4bf912282a34b58b6b35d8f7e6be535770c89c76",
        "short": "[rh:urllib] Remove dot segments during URL normalization (#7662)",
        "authors": ["coletdjnz"]
    },
    {
        "action": "change",
        "when": "59e92b1f1833440bb2190f847eb735cf0f90bc85",
        "short": "[rh:urllib] Simplify gzip decoding (#7611)",
        "authors": ["Grub4K"]
    },
    {
        "action": "add",
        "when": "c1d71d0d9f41db5e4306c86af232f5f6220a130b",
        "short": "[priority] **The minimum *recommended* Python version has been raised to 3.8**\nSince Python 3.7 has reached end-of-life, support for it will be dropped soon. [Read more](https://github.com/yt-dlp/yt-dlp/issues/7803)"
    },
    {
        "action": "add",
        "when": "61bdf15fc7400601c3da1aa7a43917310a5bf391",
        "short": "[priority] Security: [[CVE-2023-40581](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-40581)] [Prevent RCE when using `--exec` with `%q` on Windows](https://github.com/yt-dlp/yt-dlp/security/advisories/GHSA-42h4-v29r-42qg)\n    - The shell escape function is now using `\"\"` instead of `\\\"`.\n    - `utils.Popen` has been patched to properly quote commands."
    }
]
