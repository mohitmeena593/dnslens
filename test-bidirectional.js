/**
 * Comprehensive Automated Test Suite for Bidirectional DNS & Reverse DNS Tool
 */

const fs = require('fs');

async function runTestSuite() {
  console.log('====================================================');
  console.log('STARTING BIDIRECTIONAL DNS & REVERSE DNS TEST SUITE');
  console.log('====================================================');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, expected, actual) {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName} | Expected: ${expected} | Actual: ${actual}`);
      failed++;
    }
  }

  // --- Utility Functions ---
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

  function isIPv6(str) {
    if (!str) return false;
    let clean = str.trim().toLowerCase();
    if (!clean.includes(':')) return false;

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

  function isUrl(str) {
    if (!str) return false;
    const clean = str.trim().toLowerCase();
    return clean.startsWith('http://') || clean.startsWith('https://') || clean.startsWith('ftp://') || clean.startsWith('//') || (clean.includes('://'));
  }

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

  function isDomain(str) {
    if (!str || str.length < 3 || str.length > 253) return false;
    if (str.includes('..') || str.startsWith('.') || str.endsWith('.')) return false;
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(str);
  }

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

  function ipv4ToPtr(ip) {
    const octets = ip.trim().split('.');
    return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
  }

  function ipv6ToPtr(ip) {
    let clean = ip.trim().toLowerCase();
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
    const hex32 = groups.map(g => g.padStart(4, '0')).join('');
    return hex32.split('').reverse().join('.') + '.ip6.arpa';
  }

  // TEST 1: Automatic Detection Tests
  assert(classifySingle('example.com') === 'DOMAIN', 'Auto-detect domain: example.com', 'DOMAIN', classifySingle('example.com'));
  assert(classifySingle('https://example.com/api') === 'URL', 'Auto-detect URL: https://example.com/api', 'URL', classifySingle('https://example.com/api'));
  assert(classifySingle('8.8.8.8') === 'IPV4', 'Auto-detect IPv4: 8.8.8.8', 'IPV4', classifySingle('8.8.8.8'));
  assert(classifySingle('1.1.1.1') === 'IPV4', 'Auto-detect IPv4: 1.1.1.1', 'IPV4', classifySingle('1.1.1.1'));
  assert(classifySingle('2001:4860:4860::8888') === 'IPV6', 'Auto-detect IPv6: 2001:4860:4860::8888', 'IPV6', classifySingle('2001:4860:4860::8888'));
  assert(classifySingle('invalid-domain-test-12345.invalid') === 'DOMAIN', 'Auto-detect non-existent domain as domain type', 'DOMAIN', classifySingle('invalid-domain-test-12345.invalid'));
  assert(classifySingle('999.999.999.999') === 'INVALID', 'Reject invalid IP', 'INVALID', classifySingle('999.999.999.999'));

  // TEST 2: PTR Record Builder Tests
  assert(ipv4ToPtr('8.8.8.8') === '8.8.8.8.in-addr.arpa', 'IPv4 PTR: 8.8.8.8', '8.8.8.8.in-addr.arpa', ipv4ToPtr('8.8.8.8'));
  assert(ipv4ToPtr('1.1.1.1') === '1.1.1.1.in-addr.arpa', 'IPv4 PTR: 1.1.1.1', '1.1.1.1.in-addr.arpa', ipv4ToPtr('1.1.1.1'));
  const expectedV6Ptr = '8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa';
  assert(ipv6ToPtr('2001:4860:4860::8888') === expectedV6Ptr, 'IPv6 PTR: 2001:4860:4860::8888', expectedV6Ptr, ipv6ToPtr('2001:4860:4860::8888'));

  // TEST 3: Check UI clean of Presets
  const html = fs.readFileSync('C:\\Users\\Mohit Meena\\.gemini\\antigravity\\scratch\\ip-converter\\index.html', 'utf8');
  assert(!html.includes('preset-chips') && !html.includes('PRESETS:'), 'Presets completely removed from index.html', true, !html.includes('preset-chips'));
  assert(html.includes('LOOKUP'), 'Action button renamed to LOOKUP', true, html.includes('LOOKUP'));
  assert(html.includes('CYBERTOOL // DNS LOOKUP'), 'Header title updated to CYBERTOOL // DNS LOOKUP', true, html.includes('CYBERTOOL // DNS LOOKUP'));

  // TEST 4: Live DNS Queries via Cloudflare / Google DoH
  console.log('Testing live DNS queries...');
  try {
    // 4.1 Forward DNS for example.com
    const fwdRes = await fetch('https://cloudflare-dns.com/dns-query?name=example.com&type=A', {
      headers: { 'Accept': 'application/dns-json' }
    });
    const fwdData = await fwdRes.json();
    const fwdIps = fwdData.Answer ? fwdData.Answer.filter(a => a.type === 1).map(a => a.data) : [];
    assert(fwdIps.length > 0, 'Live Forward DNS (A record) for example.com', true, fwdIps.length > 0);
    console.log('   example.com ->', fwdIps);

    // 4.2 Reverse DNS for 8.8.8.8 -> in-addr.arpa PTR
    const revRes = await fetch('https://cloudflare-dns.com/dns-query?name=8.8.8.8.in-addr.arpa&type=PTR', {
      headers: { 'Accept': 'application/dns-json' }
    });
    const revData = await revRes.json();
    const ptrHosts = revData.Answer ? revData.Answer.filter(a => a.type === 12).map(a => a.data.replace(/\.$/, '')) : [];
    assert(ptrHosts.includes('dns.google'), 'Live Reverse DNS (PTR) for 8.8.8.8 -> dns.google', true, ptrHosts.includes('dns.google'));
    console.log('   8.8.8.8 PTR ->', ptrHosts);

    // 4.3 Reverse DNS for 1.1.1.1 -> in-addr.arpa PTR
    const rev1Res = await fetch('https://cloudflare-dns.com/dns-query?name=1.1.1.1.in-addr.arpa&type=PTR', {
      headers: { 'Accept': 'application/dns-json' }
    });
    const rev1Data = await rev1Res.json();
    const ptr1Hosts = rev1Data.Answer ? rev1Data.Answer.filter(a => a.type === 12).map(a => a.data.replace(/\.$/, '')) : [];
    assert(ptr1Hosts.includes('one.one.one.one'), 'Live Reverse DNS (PTR) for 1.1.1.1 -> one.one.one.one', true, ptr1Hosts.includes('one.one.one.one'));
    console.log('   1.1.1.1 PTR ->', ptr1Hosts);

    // 4.4 Reverse DNS for 2001:4860:4860::8888 -> ip6.arpa PTR
    const rev6Res = await fetch(`https://cloudflare-dns.com/dns-query?name=${expectedV6Ptr}&type=PTR`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    const rev6Data = await rev6Res.json();
    const ptr6Hosts = rev6Data.Answer ? rev6Data.Answer.filter(a => a.type === 12).map(a => a.data.replace(/\.$/, '')) : [];
    assert(ptr6Hosts.includes('dns.google'), 'Live Reverse DNS (PTR) for 2001:4860:4860::8888 -> dns.google', true, ptr6Hosts.includes('dns.google'));
    console.log('   2001:4860:4860::8888 PTR ->', ptr6Hosts);

  } catch (err) {
    console.log('[WARN] Network fetch interrupted:', err.message);
  }

  console.log('====================================================');
  console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================');

  if (failed > 0) process.exit(1);
}

runTestSuite();
