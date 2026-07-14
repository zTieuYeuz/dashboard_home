/* ═══════════════════════════════════════════════
   review.js — Tự rà soát hệ thống hằng ngày (Mechanism B, 2026-07-13).
   Worker cron (hoặc nút "Rà soát ngay") đọc dữ liệu VẬN HÀNH trong KV
   (activity_log, ai_unresolved, mcp_audit) → tổng hợp các QUAN SÁT đáng
   chú ý → đẩy 1 mục "observation" vào hàng chờ ai_insights
   (Settings › AI › 💡 Đề xuất của AI).

   HOÀN TOÀN TẤT ĐỊNH — không dùng LLM (rẻ, chắc, không bịa). Mechanism A
   (AI phân tích + đề xuất thông minh dựa trên các quan sát này) ghép sau.
   ═══════════════════════════════════════════════ */

function _rid() {
  const b = crypto.getRandomValues(new Uint8Array(6));
  return 'i_' + [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

/* opts.manual = true → chạy tay (nút bấm). Trả { added, date, count?, note? }. */
export async function runDailySelfReview(env, opts = {}) {
  const now = Date.now();
  const DAY = 24 * 60 * 60 * 1000;
  const since = now - DAY;
  const j = async (k) => (await env.DASHBOARD_KV.get(k, 'json').catch(() => null)) || [];

  const [activity, unresolved, audit] = await Promise.all([
    j('activity_log'), j('ai_unresolved'), j('mcp_audit'),
  ]);
  const recent = activity.filter(a => a && typeof a.ts === 'number' && a.ts >= since);
  const findings = [];

  // ── 1. Bảo mật đăng nhập ──
  const FAIL = new Set(['login_fail', 'login_blocked', 'login_blocked_ip', 'login_blocked_locked',
    'login_blocked_time', 'login_blocked_user', 'login_blocked_turnstile', 'mfa_fail', 'mfa_blocked']);
  const SENSITIVE = new Set(['account_locked', 'config-restore', 'force-logout-all',
    'role-change', 'set-sys-perms', 'delegate-set-manage-perms']);
  const failByUser = {}, failByIp = {}, sensitive = {};
  const lockedUsers = [];
  let loginOk = 0;
  const activeUsers = new Set();
  for (const a of recent) {
    if (FAIL.has(a.action)) {
      if (a.username && a.username !== '?') failByUser[a.username] = (failByUser[a.username] || 0) + 1;
      if (a.ip && a.ip !== '?')             failByIp[a.ip]        = (failByIp[a.ip] || 0) + 1;
    }
    if (a.action === 'login_success') { loginOk++; if (a.username && a.username !== '?') activeUsers.add(a.username); }
    if (a.action === 'account_locked' && a.username) lockedUsers.push(a.username);
    if (SENSITIVE.has(a.action)) sensitive[a.action] = (sensitive[a.action] || 0) + 1;
  }
  const badUsers = Object.entries(failByUser).filter(([, n]) => n >= 3).sort((a, b) => b[1] - a[1]);
  const badIps   = Object.entries(failByIp).filter(([, n]) => n >= 8).sort((a, b) => b[1] - a[1]);

  if (lockedUsers.length)
    findings.push(`🔒 ${lockedUsers.length} tài khoản bị khóa do thử sai quá nhiều: ${[...new Set(lockedUsers)].join(', ')}.`);
  if (badUsers.length)
    findings.push(`⚠️ Đăng nhập thất bại nhiều theo user: ${badUsers.slice(0, 5).map(([u, n]) => `${u} (${n} lần)`).join(', ')} — nghi quên mật khẩu hoặc bị dò mật khẩu.`);
  if (badIps.length)
    findings.push(`🚨 IP đăng nhập thất bại nhiều: ${badIps.slice(0, 5).map(([ip, n]) => `${ip} (${n} lần)`).join(', ')} — nghi brute-force, cân nhắc chặn IP.`);

  // ── 2. Sức khỏe AI ──
  // Nhắc theo TỔNG backlog câu hỏi chưa xử lý (không chỉ 24h) — admin nên clear dần;
  // kèm số mới trong 24h để biết xu hướng.
  const newUnresolved = unresolved.filter(u => u && u.time >= since);
  if (unresolved.length)
    findings.push(`❓ Đang tồn ${unresolved.length} câu hỏi AI chưa xử lý (${newUnresolved.length} mới trong 24h) — xem tab "Câu hỏi chưa giải quyết". Nếu lặp lại 1 chủ đề → cân nhắc thêm tài liệu (Dạy AI) hoặc tính năng mới.`);
  const toolErr = audit.filter(a => a && a.time >= since && a.ok === false);
  if (toolErr.length) {
    const byTool = {};
    for (const e of toolErr) byTool[e.tool || '?'] = (byTool[e.tool || '?'] || 0) + 1;
    findings.push(`🛠 Tool AI lỗi ${toolErr.length} lần: ${Object.entries(byTool).map(([t, n]) => `${t} (${n})`).join(', ')} — cần kiểm tra cấu hình tool.`);
  }

  // ── 3. Hành động quản trị nhạy cảm ──
  if (Object.keys(sensitive).length)
    findings.push(`🛡 Hành động quản trị nhạy cảm hôm nay: ${Object.entries(sensitive).map(([a, n]) => `${a} ×${n}`).join(', ')} — đảm bảo đều do admin chủ động (không phải bị chiếm quyền).`);

  const dateStr = new Date(now).toISOString().slice(0, 10);

  if (!findings.length) {
    return { added: false, date: dateStr,
      note: `Không có gì đáng chú ý (đăng nhập thành công: ${loginOk}, user hoạt động: ${activeUsers.size}).` };
  }

  const contextLine = `_Bối cảnh 24h: ${loginOk} lượt đăng nhập thành công, ${activeUsers.size} user hoạt động._`;
  const digest = findings.map(f => '- ' + f).join('\n') + '\n\n' + contextLine;
  const title  = `🔍 Rà soát hệ thống ${dateStr} — ${findings.length} điểm cần chú ý`;

  const list = await j('ai_insights');
  // Dedup: thay bản tự-rà-soát cùng NGÀY (tránh trùng khi bấm nút nhiều lần / cron chạy lại)
  const kept = list.filter(x => !(x && x.source === 'daily-review' && x.date === dateStr));
  kept.unshift({ id: _rid(), title, insight: digest, kind: 'observation', source: 'daily-review', date: dateStr, time: now });
  await env.DASHBOARD_KV.put('ai_insights', JSON.stringify(kept.slice(0, 200)));

  return { added: true, date: dateStr, count: findings.length, title };
}
