/**
 * Automated test suite for IPv4, IPv6, CIDR Subnetting, Hex, Binary, and Integer Conversions
 */

const fs = require('fs');

function runTestSuite() {
  console.log('==============================================');
  console.log('STARTING IP CONVERTER TEST SUITE');
  console.log('==============================================');

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

  // --- IPv4 Logic ---
  function dottedToInt(dotted) {
    const octets = dotted.trim().split('.').map(Number);
    return ((octets[0] << 24) >>> 0) + ((octets[1] << 16) >>> 0) + ((octets[2] << 8) >>> 0) + (octets[3] >>> 0);
  }

  function intToDotted(num) {
    return [ (num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255 ].join('.');
  }

  function intToHex(num) {
    return '0x' + (Number(num) >>> 0).toString(16).toUpperCase().padStart(8, '0');
  }

  function intToBinary(num) {
    const n = Number(num) >>> 0;
    return [
      ((n >>> 24) & 255).toString(2).padStart(8, '0'),
      ((n >>> 16) & 255).toString(2).padStart(8, '0'),
      ((n >>> 8) & 255).toString(2).padStart(8, '0'),
      (n & 255).toString(2).padStart(8, '0')
    ].join('.');
  }

  function intToOctal(num) {
    const n = Number(num) >>> 0;
    return [
      ((n >>> 24) & 255).toString(8).padStart(4, '0'),
      ((n >>> 16) & 255).toString(8).padStart(4, '0'),
      ((n >>> 8) & 255).toString(8).padStart(4, '0'),
      (n & 255).toString(8).padStart(4, '0')
    ].join('.');
  }

  function intToReverseDns(num) {
    const n = Number(num) >>> 0;
    return `${n & 255}.${(n >>> 8) & 255}.${(n >>> 16) & 255}.${(n >>> 24) & 255}.in-addr.arpa`;
  }

  function prefixToMask(p) {
    if (p === 0) return 0;
    return ((0xFFFFFFFF << (32 - p)) >>> 0);
  }

  // TEST 1: Dotted decimal to uint32
  const ip1 = '192.168.1.1';
  const int1 = dottedToInt(ip1);
  assert(int1 === 3232235777, 'IPv4 192.168.1.1 -> Integer 3232235777', 3232235777, int1);
  assert(intToDotted(int1) === ip1, 'Integer 3232235777 -> Dotted 192.168.1.1', ip1, intToDotted(int1));
  assert(intToHex(int1) === '0xC0A80101', 'IPv4 Hexadecimal conversion', '0xC0A80101', intToHex(int1));
  assert(intToBinary(int1) === '11000000.10101000.00000001.00000001', 'IPv4 Binary conversion', '11000000.10101000.00000001.00000001', intToBinary(int1));
  assert(intToOctal(int1) === '0300.0250.0001.0001', 'IPv4 Octal conversion', '0300.0250.0001.0001', intToOctal(int1));
  assert(intToReverseDns(int1) === '1.1.168.192.in-addr.arpa', 'IPv4 Reverse DNS PTR', '1.1.168.192.in-addr.arpa', intToReverseDns(int1));

  // TEST 2: CIDR Subnetting /24
  const mask24 = prefixToMask(24);
  const wildcard24 = (~mask24) >>> 0;
  const net24 = (int1 & mask24) >>> 0;
  const bcast24 = (net24 | wildcard24) >>> 0;
  assert(intToDotted(mask24) === '255.255.255.0', '/24 Netmask is 255.255.255.0', '255.255.255.0', intToDotted(mask24));
  assert(intToDotted(wildcard24) === '0.0.0.255', '/24 Wildcard is 0.0.0.255', '0.0.0.255', intToDotted(wildcard24));
  assert(intToDotted(net24) === '192.168.1.0', '/24 Network Address is 192.168.1.0', '192.168.1.0', intToDotted(net24));
  assert(intToDotted(bcast24) === '192.168.1.255', '/24 Broadcast Address is 192.168.1.255', '192.168.1.255', intToDotted(bcast24));
  assert(intToDotted(net24 + 1) === '192.168.1.1', '/24 First Usable is 192.168.1.1', '192.168.1.1', intToDotted(net24 + 1));
  assert(intToDotted(bcast24 - 1) === '192.168.1.254', '/24 Last Usable is 192.168.1.254', '192.168.1.254', intToDotted(bcast24 - 1));

  // TEST 3: CIDR Subnetting Edge Cases (/31 and /32)
  const mask31 = prefixToMask(31);
  assert(intToDotted(mask31) === '255.255.255.254', '/31 Netmask is 255.255.255.254', '255.255.255.254', intToDotted(mask31));
  const mask32 = prefixToMask(32);
  assert(intToDotted(mask32) === '255.255.255.255', '/32 Netmask is 255.255.255.255', '255.255.255.255', intToDotted(mask32));

  // --- IPv6 Logic ---
  function parseIPv6ToBigInt(str) {
    let clean = str.trim().toLowerCase();
    if (!clean) return null;

    if (clean.includes('.')) {
      const lastColon = clean.lastIndexOf(':');
      if (lastColon === -1) return null;
      const v4part = clean.slice(lastColon + 1);
      const octets = v4part.split('.').map(Number);
      const v4int = ((octets[0] << 24) >>> 0) + ((octets[1] << 16) >>> 0) + ((octets[2] << 8) >>> 0) + (octets[3] >>> 0);
      const hex1 = ((v4int >>> 16) & 0xFFFF).toString(16);
      const hex2 = (v4int & 0xFFFF).toString(16);
      clean = clean.slice(0, lastColon) + ':' + hex1 + ':' + hex2;
    }

    const doubleColonCount = (clean.match(/::/g) || []).length;
    if (doubleColonCount > 1) return null;

    let groups = [];
    if (doubleColonCount === 1) {
      const parts = clean.split('::');
      const leftGroups = parts[0] ? parts[0].split(':') : [];
      const rightGroups = parts[1] ? parts[1].split(':') : [];
      const missingCount = 8 - (leftGroups.length + rightGroups.length);
      if (missingCount < 1) return null;
      groups = [...leftGroups, ...Array(missingCount).fill('0'), ...rightGroups];
    } else {
      groups = clean.split(':');
    }

    if (groups.length !== 8) return null;
    let big = 0n;
    for (let i = 0; i < 8; i++) {
      const val = BigInt(parseInt(groups[i], 16));
      big = (big << 16n) | val;
    }
    return big;
  }

  function bigIntToGroups(big) {
    const groups = [];
    let temp = big;
    for (let i = 0; i < 8; i++) {
      groups.unshift(Number(temp & 0xFFFFn));
      temp = temp >> 16n;
    }
    return groups;
  }

  function expandIPv6(big) {
    const groups = bigIntToGroups(big);
    return groups.map(g => g.toString(16).padStart(4, '0')).join(':');
  }

  function compressIPv6(big) {
    const groups = bigIntToGroups(big);
    const hexGroups = groups.map(g => g.toString(16));

    let bestStart = -1;
    let bestLen = 0;
    let currentStart = -1;
    let currentLen = 0;

    for (let i = 0; i < 8; i++) {
      if (groups[i] === 0) {
        if (currentStart === -1) currentStart = i;
        currentLen++;
        if (currentLen > bestLen) {
          bestLen = currentLen;
          bestStart = currentStart;
        }
      } else {
        currentStart = -1;
        currentLen = 0;
      }
    }

    if (bestLen < 2) return hexGroups.join(':');
    const left = hexGroups.slice(0, bestStart).join(':');
    const right = hexGroups.slice(bestStart + bestLen).join(':');
    return left + '::' + right;
  }

  function reverseDnsIPv6(big) {
    const hex = big.toString(16).padStart(32, '0');
    return hex.split('').reverse().join('.') + '.ip6.arpa';
  }

  // TEST 4: IPv6 2001:db8::1
  const v6_1 = '2001:db8::1';
  const big1 = parseIPv6ToBigInt(v6_1);
  assert(big1 !== null, 'IPv6 2001:db8::1 parses successfully', true, big1 !== null);
  assert(expandIPv6(big1) === '2001:0db8:0000:0000:0000:0000:0000:0001', 'IPv6 Expanded format', '2001:0db8:0000:0000:0000:0000:0000:0001', expandIPv6(big1));
  assert(compressIPv6(big1) === '2001:db8::1', 'IPv6 Compressed RFC 5952 format', '2001:db8::1', compressIPv6(big1));
  assert(reverseDnsIPv6(big1) === '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa', 'IPv6 Reverse DNS PTR', '1.0.0.0...8.b.d.0.1.0.0.2.ip6.arpa', reverseDnsIPv6(big1));

  // TEST 5: IPv6 Loopback ::1
  const loopBig = parseIPv6ToBigInt('::1');
  assert(compressIPv6(loopBig) === '::1', 'IPv6 Loopback compression', '::1', compressIPv6(loopBig));
  assert(expandIPv6(loopBig) === '0000:0000:0000:0000:0000:0000:0000:0001', 'IPv6 Loopback expanded', '0000:0000:0000:0000:0000:0000:0000:0001', expandIPv6(loopBig));

  // TEST 6: IPv4-Mapped IPv6 ::ffff:192.168.1.1
  const mappedBig = parseIPv6ToBigInt('::ffff:192.168.1.1');
  assert(mappedBig !== null, 'IPv4-mapped IPv6 parses successfully', true, mappedBig !== null);
  assert(expandIPv6(mappedBig) === '0000:0000:0000:0000:0000:ffff:c0a8:0101', 'IPv4-mapped IPv6 expanded hex', '0000:0000:0000:0000:0000:ffff:c0a8:0101', expandIPv6(mappedBig));

  console.log('==============================================');
  console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('==============================================');

  if (failed > 0) process.exit(1);
}

runTestSuite();
