/* grab-submit-hook.js —— 零消耗抓「提交 flag」请求（浏览器 Console 用）
 *
 * 用途：把前端真正发出的提交请求（URL + body）抓下来，但**不发给服务器**
 *       ⇒ 不消耗提交次数。抓到后把 [QWB-CAPTURED] 那行贴给父代理即可。
 *
 * ★ 上一版的坑（2026-10-31 实测炸过栈，别再用那版）：
 *   1) 没 hook open → this.__u 恒 undefined → 判断恒假 → 永远抓不到；
 *   2) `const s = XHR.prototype.send` 重跑时抓到的是**上次的 wrapper**，
 *      wrapper 调 s.apply 就是调自己 → RangeError: Maximum call stack size exceeded。
 *
 * 本版特性：
 *   - 幂等：装过就不再装（P.send.__qwbWrapper 挡板）
 *   - 原始函数在覆盖**之前**存进闭包，永不自引用
 *   - 只拦 submit 类请求，其余（轮询/公告/队伍信息）原样放行，不影响页面
 *   - 可一键卸载：__QWB_UNHOOK()；页面刷新也会全清
 *
 * 用法：
 *   F12 → Console → 整段粘贴 → 回车（看到「已安装」）
 *   → 在页面上正常点一次「提交」（填个 flag{...} 形状的串）
 *   → Console 出现 [QWB-CAPTURED] {...}  → 复制那行给父代理
 *   → __QWB_UNHOOK() 卸掉（或直接刷新页面）
 */
(() => {
  const P = XMLHttpRequest.prototype;

  // ① 幂等挡板：已经装过就别再套一层
  if (P.send && P.send.__qwbWrapper) {
    console.log('[QWB] 已经装过了，不重复安装。当前已抓：', window.__QWB_CAPTURED || []);
    return;
  }

  // ② ★ 原始函数必须在覆盖之前存好（这是上一版炸栈的根因）
  const origOpen = P.open;
  const origSend = P.send;

  P.open = function (method, url) {
    this.__qwbUrl = String(url || '');
    return origOpen.apply(this, arguments);
  };

  const wrapper = function (body) {
    const url = this.__qwbUrl || '';
    // 只认「以 /submit 结尾」的端点；别用宽松的 includes('submit')，
    // 否则 /match/flag/submit_lists（看提交记录）也会被拦，页面会缺数据
    if (/\/submit(\?|$)/i.test(url)) {
      window.__QWB_CAPTURED = window.__QWB_CAPTURED || [];
      window.__QWB_CAPTURED.push({ url: url, body: body, time: new Date().toISOString() });
      console.log('[QWB-CAPTURED]', url, body);
      // ③ 不转发 ⇒ 请求不出网 ⇒ 不消耗次数；但要给 axios 一个结束信号，免得页面一直转圈
      const self = this;
      setTimeout(() => {
        try { self.dispatchEvent(new Event('error')); } catch (e) {}
        try { self.dispatchEvent(new Event('loadend')); } catch (e) {}
      }, 0);
      return;
    }
    // ④ 非提交请求：原样放行（页面轮询照常工作）
    return origSend.apply(this, arguments);
  };
  wrapper.__qwbWrapper = true;
  P.send = wrapper;

  window.__QWB_UNHOOK = () => {
    P.open = origOpen;
    P.send = origSend;
    console.log('[QWB] 已卸载');
  };

  console.log('[QWB] 已安装：submit 类请求会被拦截记录（不发出去），其余照常。'
            + ' 卸载：__QWB_UNHOOK()，或刷新页面');
})();
