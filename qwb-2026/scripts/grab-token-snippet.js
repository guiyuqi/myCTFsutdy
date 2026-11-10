// 在 ycb-bk.dasctf.com 页面按 F12 → Console，整段粘贴回车。
// 作用：把 SPA 真正发出去的 token 复制到剪贴板（不用手抄、不会抄错）。
// 取的是界面实际使用的那个：TEMPORARY_USER 用 jwtToken-1750，否则 jwtToken。
(function () {
  var code = '1750';
  var origin = localStorage.getItem('playerOrigin-' + code);
  var tok = origin === 'TEMPORARY_USER'
    ? localStorage.getItem('jwtToken-' + code)
    : (localStorage.getItem('jwtToken') || localStorage.getItem('jwtToken-' + code));
  if (!tok) {
    console.warn('没找到 token。playerOrigin=' + origin +
      '\n请先在这个页面登录（URL 要含 /compete/1750/），登录后再跑一次。');
    return;
  }
  var parts = tok.split('.');
  try {
    var p = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    console.log('token 属于:', p.username, '| relationId:', p.relationId, '| origin:', p.playerOrigin);
  } catch (e) { console.log('token 前 12 位:', tok.slice(0, 12)); }
  copy(tok);
  console.log('%c已复制到剪贴板（长度 ' + tok.length + '）→ 立刻跑 set-token.sh 粘贴', 'color:#0a0;font-weight:bold');
  return tok;
})();
