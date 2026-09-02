/**
 * ============================================================================
 * CYBERTOOL // PRODUCTION BIDIRECTIONAL DNS & REVERSE DNS ENGINE
 * Automatic detection for Domain/URL -> Forward DNS (A/AAAA) and
 * IPv4/IPv6 -> Reverse DNS (PTR) via browser-compatible DNS-over-HTTPS.
 * ============================================================================
 */

(function () {
  'use strict';

  // --- DOM Elements ---
  const dnsInput = document.getElementById('dns-input');
  const btnLookup = document.getElementById('btn-lookup');
  const btnClear = document.getElementById('btn-clear');
  const btnPaste = document.getElementById('btn-paste');
  const btnCopyAll = document.getElementById('btn-copy-all');
  const btnDownload = document.getElementById('btn-download');
  const terminalScreen = document.getElementById('terminal-screen');
  const streamLabelEl = document.getElementById('stream-label');
  const modeBadgeEl = document.getElementById('detected-mode-badge');
  const charCountEl = document.getElementById('char-count');
  const lineCountEl = document.getElementById('line-count');
  const toastEl = document.getElementById('toast');

  let rawTerminalOutputText = '';

  // ==========================================================================
  // INPUT CLASSIFICATION & VALIDATION
  // ==========================================================================

  /**
   * Validate IPv4 dotted-decimal syntax.
   */
  function isIPv4(str) {
    if (!str) return false;
    const parts = str.trim().split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => {
      if (!/^\d+$/.test(p)) return false;
      const num = Number(p);
      return num >= 0 && num <= 255 && (p === '0' || !p.startsWith('0'));
    });
  }

  /**
   * Validate IPv6 address syntax.
   */
  function isIPv6(str) {
    if (!str) return false;
    let clean = str.trim().toLowerCase();
    if (!clean.includes(':')) return false;

    // Handle IPv4-mapped IPv6 (::ffff:192.168.1.1)
    if (clean.includes('.')) {
      const lastColon = clean.lastIndexOf(':');
      if (lastColon === -1) return false;
      const v4part = clean.slice(lastColon + 1);
      if (!isIPv4(v4part)) return false;
      clean = clean.slice(0, lastColon) + ':0:0';
    }

    const doubleColonCount = (clean.match(/::/g) || []).length;
    if (doubleColonCount > 1) return false;

    let groups = [];
    if (doubleColonCount === 1) {
      const [left, right] = clean.split('::');
      const leftGroups = left ? left.split(':') : [];
      const rightGroups = right ? right.split(':') : [];
      const missing = 8 - (leftGroups.length + rightGroups.length);
      if (missing < 1) return false;
      groups = [...leftGroups, ...Array(missing).fill('0'), ...rightGroups];
    } else {
      groups = clean.split(':');
    }

    if (groups.length !== 8) return false;
    return groups.every(g => /^[0-9a-f]{1,4}$/i.test(g));
  }

  /**
   * Check if input represents a URL.
   */
  function isUrl(str) {
    if (!str) return false;
    const clean = str.trim().toLowerCase();
    return clean.startsWith('http://') || clean.startsWith('https://') || clean.startsWith('ftp://') || clean.startsWith('//') || (clean.includes('://'));
  }

  /**
   * Extract hostname from raw string, domain, or URL.
   */
  function extractHostname(inputStr) {
    if (!inputStr) return '';
    let str = inputStr.trim();
    str = str.replace(/^["'\[<]+|["'\]>]+$/g, '');

    if (str.includes('://')) {
      str = str.split('://')[1];
    } else if (str.startsWith('//')) {
      str = str.slice(2);
    }

    str = str.split('/')[0];
    str = str.split('?')[0];
    str = str.split('#')[0];

    if (!str.includes('[') && str.includes(':')) {
      const parts = str.split(':');
      if (parts.length === 2 && /^\d+$/.test(parts[1])) {
        str = parts[0];
      }
    }
    return str.trim().toLowerCase();
  }

  /**
   * Validate standard domain name syntax.
   */
  function isDomain(str) {
    if (!str || str.length < 3 || str.length > 253) return false;
    if (str.includes('..') || str.startsWith('.') || str.endsWith('.')) return false;
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(str);
  }

  /**
   * Classify single input string.
   */
  function classifySingle(item) {
    const clean = item.trim();
    if (!clean) return 'EMPTY';
    if (isIPv4(clean)) return 'IPV4';
    if (isIPv6(clean)) return 'IPV6';
    if (isUrl(clean)) {
      const host = extractHostname(clean);
      if (isIPv4(host)) return 'IPV4';
      if (isIPv6(host)) return 'IPV6';
      if (isDomain(host)) return 'URL';
    }
    if (isDomain(extractHostname(clean))) return 'DOMAIN';
    return 'INVALID';
  }

  // ==========================================================================
  // REVERSE DNS (PTR) ARPA BUILDERS
  // ==========================================================================

  /**
   * Convert IPv4 (e.g. 8.8.8.8) to in-addr.arpa pointer.
   */
  function ipv4ToPtr(ip) {
    const octets = ip.trim().split('.');
    return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
  }

  /**
   * Convert IPv6 to ip6.arpa nibble pointer.
   */
  function ipv6ToPtr(ip) {
    let clean = ip.trim().toLowerCase();

    // Handle IPv4-mapped IPv6
    if (clean.includes('.')) {
      const lastColon = clean.lastIndexOf(':');
      const v4part = clean.slice(lastColon + 1);
      const octets = v4part.split('.').map(Number);
      const hex1 = ((octets[0] << 8) | octets[1]).toString(16).padStart(4, '0');
      const hex2 = ((octets[2] << 8) | octets[3]).toString(16).padStart(4, '0');
      clean = `${clean.slice(0, lastColon)}:${hex1}:${hex2}`;
    }

    let groups = [];
    if (clean.includes('::')) {
      const [left, right] = clean.split('::');
      const leftGroups = left ? left.split(':') : [];
      const rightGroups = right ? right.split(':') : [];
      const missing = 8 - (leftGroups.length + rightGroups.length);
      groups = [...leftGroups, ...Array(missing).fill('0'), ...rightGroups];
    } else {
      groups = clean.split(':');
    }

    // Expand all 8 groups to 4 hex digits each -> 32 hex nibbles
    const hex32 = groups.map(g => g.padStart(4, '0')).join('');
    // Reverse nibbles and join with dots
    return hex32.split('').reverse().join('.') + '.ip6.arpa';
  }

  // ==========================================================================
  // REAL DNS-OVER-HTTPS (DoH) RESOLVER
  // ==========================================================================

  const DnsEngine = {
    /**
     * Query DNS record via Cloudflare DoH with Google DoH fallback.
     */
    async queryRecord(queryName, type) {
      const typeCodeMap = { 'A': 1, 'AAAA': 28, 'PTR': 12 };
      const typeCode = typeCodeMap[type] || 1;

      // 1. Cloudflare DoH
      try {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(queryName)}&type=${type}`;
        const res = await fetch(url, {
          headers: { 'Accept': 'application/dns-json' },
          signal: AbortSignal.timeout(4500)
        });
        if (res.ok) {
          const data = await res.json();
          if (data.Answer && Array.isArray(data.Answer)) {
            const records = data.Answer
              .filter(ans => ans.type === typeCode && ans.data)
              .map(ans => ans.data.trim().replace(/\.$/, '')); // strip trailing DNS root dot
            if (records.length > 0) return records;
          }
        }
      } catch (err) {
        // Fallback
      }

      // 2. Google DoH Fallback
      try {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(queryName)}&type=${type}`;
        const res = await fetch(url, {
          headers: { 'Accept': 'application/dns-json' },
          signal: AbortSignal.timeout(4500)
        });
        if (res.ok) {
          const data = await res.json();
          if (data.Answer && Array.isArray(data.Answer)) {
            const records = data.Answer
              .filter(ans => ans.type === typeCode && ans.data)
              .map(ans => ans.data.trim().replace(/\.$/, ''));
            if (records.length > 0) return records;
          }
        }
      } catch (err) {
        // Fallback
      }

      return [];
    },

    /**
     * Perform Forward DNS Lookup (Domain/URL -> IPv4 & IPv6).
     */
    async forwardLookup(domain) {
      try {
        const [ipv4Records, ipv6Records] = await Promise.all([
          this.queryRecord(domain, 'A'),
          this.queryRecord(domain, 'AAAA')
        ]);

        const hasIpv4 = ipv4Records.length > 0;
        const hasIpv6 = ipv6Records.length > 0;

        if (hasIpv4 || hasIpv6) {
          return {
            lookupMode: 'FORWARD',
            domain,
            ipv4: ipv4Records,
            ipv6: ipv6Records,
            status: 'RESOLVED',
            success: true
          };
        } else {
          return {
            lookupMode: 'FORWARD',
            domain,
            ipv4: [],
            ipv6: [],
            status: 'NXDOMAIN / UNRESOLVED',
            success: false,
            error: 'No active A or AAAA DNS records found.'
          };
        }
      } catch (err) {
        return {
          lookupMode: 'FORWARD',
          domain,
          ipv4: [],
          ipv6: [],
          status: 'DNS QUERY FAILED',
          success: false,
          error: 'Unable to reach DNS resolver. Check network connection.'
        };
      }
    },

    /**
     * Perform Reverse DNS Lookup (IPv4/IPv6 -> Hostname PTR).
     */
    async reverseLookup(ip, isV6 = false) {
      const ptrName = isV6 ? ipv6ToPtr(ip) : ipv4ToPtr(ip);

      try {
        const hostnames = await this.queryRecord(ptrName, 'PTR');

        if (hostnames.length > 0) {
          return {
            lookupMode: 'REVERSE',
            ip,
            hostnames,
            ptrName,
            status: 'RESOLVED',
            hasPtr: true,
            success: true
          };
        } else {
          return {
            lookupMode: 'REVERSE',
            ip,
            hostnames: [],
            ptrName,
            status: 'NO REVERSE DNS RECORD',
            hasPtr: false,
            success: true // graceful resolution with no PTR
          };
        }
      } catch (err) {
        return {
          lookupMode: 'REVERSE',
          ip,
          hostnames: [],
          ptrName,
          status: 'REVERSE DNS QUERY FAILED',
          hasPtr: false,
          success: false,
          error: 'Reverse DNS query failed.'
        };
      }
    },

    /**
     * Unified Dispatcher for any single input.
     */
    async executeItem(raw) {
      const type = classifySingle(raw);

      if (type === 'IPV4') {
        return await this.reverseLookup(raw.trim(), false);
      } else if (type === 'IPV6') {
        return await this.reverseLookup(raw.trim(), true);
      } else if (type === 'DOMAIN' || type === 'URL') {
        const hostname = extractHostname(raw);
        return await this.forwardLookup(hostname);
      } else {
        return {
          lookupMode: 'INVALID',
          input: raw,
          status: 'INVALID INPUT',
          success: false,
          error: 'Please enter a valid domain (e.g. example.com), URL, IPv4 address (e.g. 8.8.8.8), or IPv6 address.'
        };
      }
    }
  };

  // ==========================================================================
  // UI & LIVE CLASSIFIER CONTROLLER
  // ==========================================================================

  function showToast(message) {
    if (!toastEl) return;
    toastEl.textContent = message;
    toastEl.classList.add('show');
    clearTimeout(toastEl._timer);
    toastEl._timer = setTimeout(() => {
      toastEl.classList.remove('show');
    }, 2400);
  }

  function copyToClipboard(text, label = 'Copied') {
    if (!navigator.clipboard) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(`${label} to clipboard!`);
      return;
    }

    navigator.clipboard.writeText(text).then(() => {
      showToast(`${label} to clipboard!`);
    }).catch(() => {
      showToast('Copy failed. Check clipboard permissions.');
    });
  }

  function updateLiveClassifier() {
    const val = dnsInput.value;
    const chars = val.length;
    const lines = val.trim() ? val.split(/\r\n|\r|\n/).filter(l => l.trim()).length : 0;

    charCountEl.textContent = chars.toLocaleString();
    lineCountEl.textContent = lines.toLocaleString();

    if (!val.trim()) {
      streamLabelEl.textContent = 'DOMAIN INPUT';
      modeBadgeEl.textContent = 'AUTO DETECT';
      return;
    }

    if (lines > 1) {
      streamLabelEl.textContent = 'BATCH INPUT';
      modeBadgeEl.textContent = `BATCH STREAM (${lines})`;
      return;
    }

    const type = classifySingle(val.trim());
    if (type === 'IPV4') {
      streamLabelEl.textContent = 'IP INPUT';
      modeBadgeEl.textContent = 'IPv4 DETECTED';
    } else if (type === 'IPV6') {
      streamLabelEl.textContent = 'IP INPUT';
      modeBadgeEl.textContent = 'IPv6 DETECTED';
    } else if (type === 'URL') {
      streamLabelEl.textContent = 'URL INPUT';
      modeBadgeEl.textContent = 'URL DETECTED';
    } else if (type === 'DOMAIN') {
      streamLabelEl.textContent = 'DOMAIN INPUT';
      modeBadgeEl.textContent = 'DOMAIN DETECTED';
    } else {
      streamLabelEl.textContent = 'INPUT STREAM';
      modeBadgeEl.textContent = 'INVALID INPUT';
    }
  }

  function clearTerminal() {
    terminalScreen.innerHTML = `
      <div class="terminal-line log-init">
        <span class="prompt-symbol">&gt;</span> <span class="log-text">System initialized ...</span>
      </div>
      <div class="terminal-line log-ready">
        <span class="prompt-symbol">&gt;</span> <span class="log-text">Ready for input stream ...</span>
      </div>
    `;
    rawTerminalOutputText = `> System initialized ...\n> Ready for input stream ...\n`;
  }

  // ==========================================================================
  // CARD RENDERERS (Exact User Specifications)
  // ==========================================================================

  /**
   * Render Forward DNS Record card (Domain -> IP).
   */
  function renderForwardCard(res) {
    const isResolved = res.status === 'RESOLVED';
    const statusClass = isResolved ? 'status-resolved' : 'status-failed';

    const ipv4Display = res.ipv4.length > 0
      ? res.ipv4.join(', ')
      : '<span class="log-dim">None detected</span>';

    const ipv6Display = res.ipv6.length > 0
      ? res.ipv6.join(', ')
      : '<span class="log-dim">None detected</span>';

    let html = `
      <div class="terminal-line">
        <span class="prompt-symbol">&gt;</span> <span class="log-cyan">[+] DNS QUERY COMPLETED:</span> <span class="log-white">${res.domain}</span>
      </div>
      
      <div class="t-block">
        <div class="t-header">
          <span>DNS RESOLUTION RECORD</span>
          <span class="t-val status-badge ${statusClass}">${res.status}</span>
        </div>
        <div class="t-grid">
          <div class="t-label">DOMAIN</div>
          <div class="t-val">${res.domain}</div>
          <button class="t-copy-btn" data-copy="${res.domain}">COPY</button>

          <div class="t-label">IPv4 ADDRESS</div>
          <div class="t-val log-green">${ipv4Display}</div>
          ${res.ipv4.length > 0 ? `<button class="t-copy-btn" data-copy="${res.ipv4.join(', ')}">COPY</button>` : '<div></div>'}

          <div class="t-label">IPv6 ADDRESS</div>
          <div class="t-val log-cyan">${ipv6Display}</div>
          ${res.ipv6.length > 0 ? `<button class="t-copy-btn" data-copy="${res.ipv6.join(', ')}">COPY</button>` : '<div></div>'}

          <div class="t-label">DNS STATUS</div>
          <div class="t-val ${isResolved ? 'log-green' : 'log-red'}">${res.status}</div>
          <button class="t-copy-btn" data-copy="${res.status}">COPY</button>
        </div>
      </div>
    `;

    if (!isResolved && res.error) {
      html += `
        <div class="terminal-line">
          <span class="prompt-symbol">&gt;</span> <span class="log-red">[!] Notice: ${res.error}</span>
        </div>
      `;
    }

    return html;
  }

  /**
   * Render Reverse DNS Record card (IP -> Hostname).
   */
  function renderReverseCard(res) {
    if (res.hasPtr) {
      // Case 2: PTR Found
      return `
        <div class="terminal-line">
          <span class="prompt-symbol">&gt;</span> <span class="log-cyan">[+] REVERSE DNS QUERY COMPLETED:</span> <span class="log-white">${res.ip}</span>
        </div>
        
        <div class="t-block">
          <div class="t-header">
            <span>REVERSE DNS RECORD</span>
            <span class="t-val status-badge status-resolved">RESOLVED</span>
          </div>
          <div class="t-grid">
            <div class="t-label">IP ADDRESS</div>
            <div class="t-val log-cyan">${res.ip}</div>
            <button class="t-copy-btn" data-copy="${res.ip}">COPY</button>

            <div class="t-label">HOSTNAME</div>
            <div class="t-val log-green">${res.hostnames.join(', ')}</div>
            <button class="t-copy-btn" data-copy="${res.hostnames.join(', ')}">COPY</button>

            <div class="t-label">LOOKUP TYPE</div>
            <div class="t-val log-white">PTR / REVERSE DNS</div>
            <div></div>

            <div class="t-label">DNS STATUS</div>
            <div class="t-val log-green">RESOLVED</div>
            <button class="t-copy-btn" data-copy="RESOLVED">COPY</button>
          </div>
        </div>
      `;
    } else {
      // Case 3: No PTR Found (Graceful)
      return `
        <div class="terminal-line">
          <span class="prompt-symbol">&gt;</span> <span class="log-yellow">[!] REVERSE DNS COMPLETED:</span> <span class="log-white">${res.ip}</span>
        </div>
        
        <div class="t-block">
          <div class="t-header">
            <span>REVERSE DNS RECORD</span>
            <span class="t-val status-badge status-neutral">NO REVERSE DNS RECORD</span>
          </div>
          <div class="t-grid">
            <div class="t-label">IP ADDRESS</div>
            <div class="t-val log-cyan">${res.ip}</div>
            <button class="t-copy-btn" data-copy="${res.ip}">COPY</button>

            <div class="t-label">HOSTNAME</div>
            <div class="t-val log-dim">No PTR record found</div>
            <div></div>

            <div class="t-label">LOOKUP TYPE</div>
            <div class="t-val log-white">PTR / REVERSE DNS</div>
            <div></div>

            <div class="t-label">DNS STATUS</div>
            <div class="t-val log-yellow">NO REVERSE DNS RECORD</div>
            <button class="t-copy-btn" data-copy="NO REVERSE DNS RECORD">COPY</button>
          </div>
        </div>
      `;
    }
  }

  /**
   * Render Invalid Input card.
   */
  function renderInvalidCard(res) {
    return `
      <div class="terminal-line">
        <span class="prompt-symbol">&gt;</span> <span class="log-red">[!] INVALID INPUT:</span> <span class="log-white">${res.input}</span>
      </div>
      <div class="terminal-line">
        <span class="prompt-symbol">&gt;</span> <span class="log-dim">${res.error}</span>
      </div>
    `;
  }

  /**
   * Format Plain Text for export & copy-all.
   */
  function formatPlainItem(res) {
    if (res.lookupMode === 'FORWARD') {
      return [
        `=== DNS RESOLUTION RECORD ===`,
        `DOMAIN:       ${res.domain}`,
        `IPv4 ADDRESS: ${res.ipv4.length > 0 ? res.ipv4.join(', ') : 'None detected'}`,
        `IPv6 ADDRESS: ${res.ipv6.length > 0 ? res.ipv6.join(', ') : 'None detected'}`,
        `DNS STATUS:   ${res.status}`,
        res.error ? `ERROR:        ${res.error}` : ''
      ].filter(Boolean).join('\n');
    } else if (res.lookupMode === 'REVERSE') {
      return [
        `=== REVERSE DNS RECORD ===`,
        `IP ADDRESS:   ${res.ip}`,
        `HOSTNAME:     ${res.hasPtr ? res.hostnames.join(', ') : 'No PTR record found'}`,
        `LOOKUP TYPE:  PTR / REVERSE DNS`,
        `DNS STATUS:   ${res.status}`
      ].join('\n');
    } else {
      return `=== INVALID INPUT ===\nINPUT:  ${res.input}\nSTATUS: ${res.status}`;
    }
  }

  // ==========================================================================
  // MAIN LOOKUP ACTION DISPATCHER
  // ==========================================================================

  async function handleLookup() {
    const rawText = dnsInput.value.trim();
    if (!rawText) {
      terminalScreen.innerHTML = `
        <div class="terminal-line log-init">
          <span class="prompt-symbol">&gt;</span> <span class="log-red">[!] Error: Input is empty. Please enter a domain, URL, IPv4 address, or IPv6 address.</span>
        </div>
      `;
      showToast('Please enter an input to lookup');
      return;
    }

    const lines = rawText.split(/[\r\n]+/).map(l => l.trim()).filter(Boolean);

    // Set loading state
    btnLookup.disabled = true;
    btnLookup.innerHTML = `
      <svg class="spin-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.25" stroke="currentColor"></circle>
        <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor"></path>
      </svg>
      <span>RESOLVING...</span>
    `;

    // Process all lines
    terminalScreen.innerHTML = `
      <div class="terminal-line">
        <span class="prompt-symbol">&gt;</span> <span class="log-cyan">Initiating query stream ...</span>
      </div>
    `;

    const results = [];
    let combinedHtml = '';
    const plainOutputs = [];

    for (let i = 0; i < lines.length; i++) {
      const item = lines[i];
      const res = await DnsEngine.executeItem(item);
      results.push(res);

      if (res.lookupMode === 'FORWARD') {
        combinedHtml += renderForwardCard(res);
      } else if (res.lookupMode === 'REVERSE') {
        combinedHtml += renderReverseCard(res);
      } else {
        combinedHtml += renderInvalidCard(res);
      }

      plainOutputs.push(formatPlainItem(res));
    }

    terminalScreen.innerHTML = combinedHtml;
    rawTerminalOutputText = plainOutputs.join('\n\n');
    terminalScreen.scrollTop = 0;

    // Reset button
    btnLookup.disabled = false;
    btnLookup.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <circle cx="11" cy="11" r="8"></circle>
        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      </svg>
      <span>LOOKUP</span>
    `;

    attachCopyListeners();
    showToast('Lookup Complete');
  }

  // Attach dynamic copy listeners inside terminal
  function attachCopyListeners() {
    const copyBtns = terminalScreen.querySelectorAll('.t-copy-btn[data-copy]');
    copyBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const textToCopy = btn.getAttribute('data-copy');
        if (textToCopy) {
          copyToClipboard(textToCopy, 'Record copied');
          btn.textContent = 'COPIED!';
          btn.style.background = '#00a8ff';
          btn.style.color = '#ffffff';
          setTimeout(() => {
            btn.textContent = 'COPY';
            btn.style.background = '';
            btn.style.color = '';
          }, 1500);
        }
      });
    });
  }

  // ==========================================================================
  // EVENT LISTENERS & SHORTCUTS
  // ==========================================================================

  // Live input events for automatic classifier
  dnsInput.addEventListener('input', updateLiveClassifier);
  dnsInput.addEventListener('keydown', (e) => {
    // Pressing Enter (without Shift) triggers lookup directly
    // Shift+Enter allows creating a new line for batch multi-line input
    if (e.key === 'Enter') {
      if (e.shiftKey) {
        return; // Allow newline with Shift+Enter
      }
      e.preventDefault();
      handleLookup();
    }
  });

  // Lookup button
  btnLookup.addEventListener('click', handleLookup);

  // Clear button
  btnClear.addEventListener('click', () => {
    dnsInput.value = '';
    updateLiveClassifier();
    clearTerminal();
    showToast('Input and terminal cleared');
  });

  // Quick Paste button
  btnPaste.addEventListener('click', async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          dnsInput.value = text;
          updateLiveClassifier();
          showToast('Pasted from clipboard');
          handleLookup();
        } else {
          showToast('Clipboard is empty');
        }
      } else {
        dnsInput.focus();
        showToast('Use Ctrl+V to paste');
      }
    } catch (err) {
      dnsInput.focus();
      showToast('Clipboard access denied. Use Ctrl+V');
    }
  });

  // Copy All button
  btnCopyAll.addEventListener('click', () => {
    const textToCopy = rawTerminalOutputText || terminalScreen.innerText;
    if (!textToCopy || textToCopy.includes('Ready for input stream ...')) {
      showToast('Terminal is empty. Perform a lookup first!');
      return;
    }
    copyToClipboard(textToCopy, 'Entire results log copied');
  });

  // Export / Download button
  btnDownload.addEventListener('click', () => {
    const textToExport = rawTerminalOutputText || terminalScreen.innerText;
    if (!textToExport || textToExport.includes('Ready for input stream ...')) {
      showToast('No lookup data to export');
      return;
    }

    const blob = new Blob([textToExport], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `dns-lookup-report-${Date.now()}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('Exported results as TXT file');
  });

  // Initialize
  updateLiveClassifier();
  clearTerminal();

})();
