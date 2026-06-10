/* ScamGuard scanner engine
 * Pure client-side rule-based scoring. No network requests, no external API.
 */
(function attachScanner(global) {
  'use strict';

  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
    'cutt.ly', 'rebrand.ly', 's.id', 'bom.so', 'shorturl.at', 'bitly.com',
    'lnkd.in', 'zalo.me', 'shope.ee', 'fb.watch', 'youtu.be'
  ]);

  const SUSPICIOUS_TLDS = new Set([
    'top', 'xyz', 'click', 'work', 'rest', 'monster', 'cyou', 'gq', 'tk',
    'ml', 'cf', 'icu', 'buzz', 'quest', 'zip', 'mov', 'lol', 'live'
  ]);

  const OFFICIAL_DOMAINS = {
    facebook: ['facebook.com', 'fb.com', 'messenger.com'],
    meta: ['meta.com', 'facebook.com'],
    google: ['google.com', 'gmail.com', 'google.com.vn', 'youtube.com', 'youtu.be'],
    gmail: ['gmail.com', 'google.com'],
    microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
    outlook: ['outlook.com', 'live.com', 'microsoft.com'],
    apple: ['apple.com', 'icloud.com'],
    icloud: ['icloud.com', 'apple.com'],
    steam: ['steampowered.com', 'steamcommunity.com'],
    discord: ['discord.com', 'discord.gg'],
    telegram: ['telegram.org', 't.me'],
    paypal: ['paypal.com'],
    shopee: ['shopee.vn', 'shopee.com'],
    lazada: ['lazada.vn'],
    tiki: ['tiki.vn'],
    momo: ['momo.vn'],
    zalopay: ['zalopay.vn'],
    zalo: ['zalo.me', 'zaloapp.com'],
    mbbank: ['mbbank.com.vn'],
    vietcombank: ['vietcombank.com.vn', 'vcb.com.vn'],
    techcombank: ['techcombank.com'],
    bidv: ['bidv.com.vn'],
    vietinbank: ['vietinbank.vn'],
    agribank: ['agribank.com.vn'],
    acb: ['acb.com.vn'],
    sacombank: ['sacombank.com.vn'],
    fpt: ['fpt.edu.vn', 'fpt.com.vn'],
    coursera: ['coursera.org'],
    github: ['github.com'],
    openai: ['openai.com', 'chatgpt.com']
  };

  const VIETNAMESE_SCAM_TERMS = [
    'xác minh tài khoản', 'tài khoản bị khóa', 'khoá tài khoản', 'khóa tài khoản',
    'đăng nhập để xác minh', 'nhập mã otp', 'cung cấp otp', 'mã xác thực',
    'mật khẩu', 'khôi phục tài khoản', 'hoàn tiền', 'nhận thưởng', 'trúng thưởng',
    'quà tặng', 'miễn phí', 'chuyển khoản', 'phí xác nhận', 'phí nhận thưởng',
    'cập nhật thông tin', 'thông tin ngân hàng', 'thẻ bị khóa', 'ví điện tử',
    'bấm vào link', 'nhấn vào link', 'link bên dưới', 'khẩn cấp', 'ngay lập tức',
    'trong vòng 24h', 'trong 24 giờ', 'nếu không sẽ', 'xóa tài khoản',
    'vi phạm chính sách', 'mở khóa', 'xác nhận danh tính', 'nhận tiền', 'nạp tiền',
    'đầu tư lợi nhuận', 'lãi suất cao', 'việc nhẹ lương cao'
  ];

  const ENGLISH_SCAM_TERMS = [
    'verify your account', 'account locked', 'account suspended', 'password reset',
    'enter your password', 'one time password', 'otp code', 'security alert',
    'unusual login', 'confirm your identity', 'click the link', 'click here',
    'limited time', 'urgent action required', 'act now', 'final warning',
    'free gift', 'giveaway', 'refund', 'payment failed', 'billing issue',
    'wallet verification', 'crypto investment', 'guaranteed profit',
    'job offer', 'work from home', 'easy money', 'claim your prize'
  ];

  const CREDENTIAL_TERMS = [
    'password', 'mật khẩu', 'otp', 'mã otp', 'mã xác thực', '2fa', 'two factor',
    'security code', 'recovery code', 'private key', 'seed phrase', 'cvv', 'pin'
  ];

  function normalizeText(text) {
    return String(text || '')
      .normalize('NFKC')
      .replace(/[\u200B-\u200D\uFEFF]/g, '')
      .toLowerCase();
  }

  function clamp(num, min, max) {
    return Math.min(max, Math.max(min, num));
  }

  function safeHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    } catch {
      return '';
    }
  }

  function rootDomain(hostname) {
    if (!hostname) return '';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;
    const parts = hostname.split('.').filter(Boolean);
    if (parts.length <= 2) return hostname;
    const twoPartSuffixes = new Set([
      'com.vn', 'edu.vn', 'gov.vn', 'net.vn', 'org.vn', 'co.uk', 'com.au', 'co.jp'
    ]);
    const lastTwo = parts.slice(-2).join('.');
    if (twoPartSuffixes.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return lastTwo;
  }

  function isOfficialForBrand(hostname, brand) {
    const root = rootDomain(hostname);
    return (OFFICIAL_DOMAINS[brand] || []).some((official) => {
      const cleanOfficial = official.replace(/^www\./, '');
      return hostname === cleanOfficial || hostname.endsWith('.' + cleanOfficial) || root === cleanOfficial;
    });
  }

  function extractUrls(text) {
    const raw = String(text || '');
    const matches = raw.match(/(?:https?:\/\/|www\.)[^\s<>'"`),;]+/gi) || [];
    return matches.map((url) => url.startsWith('www.') ? 'https://' + url : url);
  }

  function scoreToLevel(score) {
    if (score >= 75) return 'high';
    if (score >= 45) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
  }

  function addFinding(findings, points, title, detail, severity = 'medium') {
    findings.push({ points, title, detail, severity });
  }

  function analyzeUrl(url) {
    const findings = [];
    let score = 0;
    let parsed = null;

    try {
      parsed = new URL(url.startsWith('www.') ? 'https://' + url : url);
    } catch {
      addFinding(findings, 10, 'URL không hợp lệ', 'Link có định dạng lạ hoặc bị che giấu.', 'low');
      return { url, score: 10, level: scoreToLevel(10), findings, hostname: '' };
    }

    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');
    const root = rootDomain(hostname);
    const path = decodeURIComponent(parsed.pathname + parsed.search).toLowerCase();
    const tld = root.split('.').pop();
    const hostAndPath = `${hostname} ${path}`;

    if (parsed.protocol !== 'https:') {
      score += 10;
      addFinding(findings, 10, 'Không dùng HTTPS', 'Trang không mã hóa HTTPS, không nên nhập mật khẩu/OTP.', 'low');
    }

    if (parsed.username || parsed.password || url.includes('@')) {
      score += 25;
      addFinding(findings, 25, 'URL có ký tự @ hoặc thông tin đăng nhập', 'Kẻ gian có thể dùng @ để đánh lừa phần domain thật.', 'high');
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 18;
      addFinding(findings, 18, 'Dùng địa chỉ IP thay vì tên miền', 'Link đăng nhập hợp lệ hiếm khi dùng IP trực tiếp.', 'medium');
    }

    if (hostname.includes('xn--')) {
      score += 22;
      addFinding(findings, 22, 'Tên miền punycode', 'Có thể là domain giả mạo bằng ký tự Unicode nhìn giống chữ thật.', 'high');
    }

    if (SHORTENERS.has(root) || SHORTENERS.has(hostname)) {
      score += 16;
      addFinding(findings, 16, 'Link rút gọn', 'Link rút gọn che giấu domain đích, nên kiểm tra kỹ trước khi mở.', 'medium');
    }

    if (SUSPICIOUS_TLDS.has(tld)) {
      score += 10;
      addFinding(findings, 10, 'Đuôi tên miền rủi ro', `Domain dùng đuôi .${tld}, cần kiểm tra thêm độ tin cậy.`, 'low');
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3 || hostname.length > 45) {
      score += 8;
      addFinding(findings, 8, 'Tên miền dài hoặc nhiều dấu gạch ngang', 'Domain lừa đảo thường cố nhồi nhiều từ khóa để trông hợp lệ.', 'low');
    }

    for (const brand of Object.keys(OFFICIAL_DOMAINS)) {
      if (hostAndPath.includes(brand) && !isOfficialForBrand(hostname, brand)) {
        score += 22;
        addFinding(
          findings,
          22,
          `Có dấu hiệu giả mạo ${brand}`,
          `Link nhắc tới ${brand} nhưng domain thật là ${hostname}.`,
          'high'
        );
        break;
      }
    }

    const credentialInUrl = CREDENTIAL_TERMS.some(term => path.includes(term));
    if (credentialInUrl) {
      score += 14;
      addFinding(findings, 14, 'URL liên quan đăng nhập/mã xác thực', 'Đường dẫn có từ khóa mật khẩu/OTP/xác thực.', 'medium');
    }

    return {
      url,
      hostname,
      rootDomain: root,
      score: clamp(score, 0, 100),
      level: scoreToLevel(score),
      findings
    };
  }

  function analyzeText(text, options = {}) {
    const normalized = normalizeText(text);
    const findings = [];
    let score = 0;

    const urls = extractUrls(text);
    const urlReports = urls.map(analyzeUrl);
    const urlScore = urlReports.reduce((max, report) => Math.max(max, report.score), 0);
    if (urlScore > 0) {
      score += Math.min(42, Math.round(urlScore * 0.55));
    }

    const matchedVi = VIETNAMESE_SCAM_TERMS.filter(term => normalized.includes(term));
    const matchedEn = ENGLISH_SCAM_TERMS.filter(term => normalized.includes(term));
    const matchedTerms = [...matchedVi, ...matchedEn];
    if (matchedTerms.length) {
      const points = Math.min(30, 8 + matchedTerms.length * 4);
      score += points;
      addFinding(
        findings,
        points,
        'Có từ khóa thường gặp trong lừa đảo',
        `Phát hiện: ${matchedTerms.slice(0, 8).join(', ')}${matchedTerms.length > 8 ? '...' : ''}`,
        matchedTerms.length >= 4 ? 'high' : 'medium'
      );
    }

    const credentialMatches = CREDENTIAL_TERMS.filter(term => normalized.includes(term));
    if (credentialMatches.length) {
      score += 15;
      addFinding(
        findings,
        15,
        'Nội dung yêu cầu thông tin nhạy cảm',
        `Có nhắc tới: ${credentialMatches.slice(0, 6).join(', ')}. Không cung cấp mã/OTP/mật khẩu qua link lạ.`,
        'high'
      );
    }

    const urgencyPatterns = [
      /khẩn cấp|ngay lập tức|trong\s+(?:24|48)\s*(?:h|giờ)|nếu không|final warning|urgent|immediately|within\s+24\s+hours/iu,
      /tài khoản.*(?:khóa|khoá|xóa|xoá|suspend|locked)|account.*(?:locked|suspended|deleted)/iu
    ];
    for (const pattern of urgencyPatterns) {
      if (pattern.test(normalized)) {
        score += 12;
        addFinding(findings, 12, 'Tạo cảm giác khẩn cấp/đe dọa', 'Scam thường ép người dùng hành động nhanh để mất cảnh giác.', 'medium');
        break;
      }
    }

    const rewardPattern = /trúng thưởng|nhận thưởng|quà tặng|miễn phí|hoàn tiền|claim.*prize|free gift|giveaway|refund/iu;
    if (rewardPattern.test(normalized)) {
      score += 12;
      addFinding(findings, 12, 'Dụ bằng quà/tiền/hoàn tiền', 'Cần kiểm tra nguồn chính thức trước khi nhập thông tin cá nhân.', 'medium');
    }

    const moneyPattern = /chuyển khoản|phí xác nhận|phí nhận thưởng|nạp tiền|đầu tư|lãi suất|guaranteed profit|crypto|investment|bank transfer/iu;
    if (moneyPattern.test(normalized)) {
      score += 14;
      addFinding(findings, 14, 'Liên quan tiền/chuyển khoản/đầu tư', 'Nên xác minh qua kênh chính thức, không chuyển tiền theo tin nhắn lạ.', 'high');
    }

    if (urls.length >= 4) {
      score += 8;
      addFinding(findings, 8, 'Nhiều link trong cùng nội dung', 'Tin nhắn nhiều link có thể dùng để gây nhiễu hoặc dẫn tới trang giả mạo.', 'low');
    }

    urlReports.forEach((report) => {
      report.findings.forEach((finding) => {
        findings.push({ ...finding, url: report.url, hostname: report.hostname });
      });
    });

    if (!normalized.trim() && urls.length === 0) {
      return {
        score: 0,
        level: 'safe',
        summary: 'Chưa có nội dung để quét.',
        findings: [],
        urlReports,
        scannedAt: new Date().toISOString()
      };
    }

    const finalScore = clamp(score, 0, 100);
    const level = scoreToLevel(finalScore);
    return {
      score: finalScore,
      level,
      summary: buildSummary(level, finalScore, findings.length, urlReports.length),
      findings: sortFindings(findings),
      urlReports,
      scannedAt: new Date().toISOString(),
      source: options.source || 'manual'
    };
  }

  function sortFindings(findings) {
    const order = { high: 0, medium: 1, low: 2 };
    return findings
      .slice()
      .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || b.points - a.points)
      .slice(0, 20);
  }

  function buildSummary(level, score, findingCount, urlCount) {
    if (level === 'high') return `RỦI RO CAO (${score}/100). Không nên đăng nhập, nhập OTP/mật khẩu hoặc chuyển tiền.`;
    if (level === 'medium') return `RỦI RO TRUNG BÌNH (${score}/100). Cần kiểm tra domain và nguồn gửi trước khi thao tác.`;
    if (level === 'low') return `RỦI RO THẤP (${score}/100). Có vài dấu hiệu cần xem kỹ.`;
    return `Có vẻ an toàn (${score}/100), nhưng vẫn nên kiểm tra nguồn chính thức nếu liên quan tài khoản/tiền.`;
  }

  function recommendation(level) {
    if (level === 'high') {
      return [
        'Không bấm link và không nhập OTP/mật khẩu.',
        'Mở website chính thức bằng cách tự gõ địa chỉ trong trình duyệt.',
        'Nếu đã nhập thông tin, đổi mật khẩu ngay và bật 2FA.',
        'Liên hệ ngân hàng/dịch vụ qua kênh chính thức nếu có liên quan tiền.'
      ];
    }
    if (level === 'medium') {
      return [
        'Kiểm tra domain thật trước khi đăng nhập.',
        'Không tải file hoặc cài extension từ nguồn lạ.',
        'Tìm thông báo tương tự trong app/website chính thức.'
      ];
    }
    return [
      'Vẫn cẩn thận với yêu cầu OTP, mật khẩu, mã khôi phục hoặc chuyển tiền.',
      'Ưu tiên mở dịch vụ từ bookmark hoặc app chính thức.'
    ];
  }

  global.SafeCheckScanner = {
    analyzeText,
    analyzeUrl,
    extractUrls,
    recommendation,
    version: '1.0.0'
  };
})(typeof window !== 'undefined' ? window : globalThis);
