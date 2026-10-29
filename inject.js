// SNI Browser — persistent in-page browser chrome (toolbar + URL bar).
// Re-injected after every navigation by the native side (webview.go).
(function () {
    if (window.__sni_injected) return;
    if (!document.body) return; // retry on a later tick
    if (window !== window.top) return; // skip iframes
    window.__sni_injected = true;

    var H = 40;

    var bar = document.createElement('div');
    bar.id = '__sni_bar';
    bar.innerHTML =
        '<button data-act="back" title="Back">\u25C0</button>' +
        '<button data-act="fwd" title="Forward">\u25B6</button>' +
        '<button data-act="reload" title="Reload">\u21BB</button>' +
        '<button data-act="home" title="Home">\u2302</button>' +
        '<input id="__sni_url" type="text" spellcheck="false" autocomplete="off" placeholder="https://...">' +
        '<span id="__sni_status" title="SNI MITM active">\uD83D\uDD12 SNI</span>';

    bar.style.cssText =
        'all:initial;position:fixed;top:0;left:0;right:0;height:' + H + 'px;' +
        'background:#16161e;color:#ccc;display:flex;align-items:center;gap:4px;' +
        'padding:0 8px;font:13px/1.2 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;' +
        'z-index:2147483647;box-shadow:0 1px 8px rgba(0,0,0,.5);box-sizing:border-box;';

    var style = document.createElement('style');
    style.textContent =
        '#__sni_bar button{all:initial;font:14px/1 sans-serif;color:#bbb;background:#262633;' +
        'border:1px solid #333;border-radius:6px;padding:5px 10px;cursor:pointer;' +
        'min-width:30px;text-align:center;box-sizing:border-box;}' +
        '#__sni_bar button:hover{background:#33334a;color:#fff;}' +
        '#__sni_bar button:active{background:#44445e;}' +
        '#__sni_bar input{flex:1;height:26px;background:#101018;border:1px solid #333;' +
        'border-radius:13px;color:#eee;padding:0 12px;font:13px/1.2 sans-serif;' +
        'outline:none;min-width:120px;box-sizing:border-box;}' +
        '#__sni_bar input:focus{border-color:#4f8;}' +
        '#__sni_bar #__sni_status{font:11px/1 sans-serif;color:#4f8;white-space:nowrap;padding:0 4px;}';

    var spacer = document.createElement('div');
    spacer.style.cssText = 'height:' + H + 'px;';

    var root = document.body;
    root.insertBefore(style, root.firstChild);
    root.insertBefore(spacer, root.firstChild);
    root.insertBefore(bar, root.firstChild);

    var input = bar.querySelector('#__sni_url');

    function updateURL() { input.value = location.href; }
    updateURL();

    var last = location.href;
    setInterval(function () {
        if (location.href !== last) { last = location.href; updateURL(); }
    }, 300);
    window.addEventListener('popstate', updateURL);
    window.addEventListener('hashchange', updateURL);

    bar.addEventListener('click', function (e) {
        var b = e.target.closest('button');
        if (!b) return;
        var act = b.getAttribute('data-act');
        if (act === 'back') { history.back(); }
        else if (act === 'fwd') { history.forward(); }
        else if (act === 'reload') { location.reload(); }
        else if (act === 'home') { location.href = 'https://www.google.com'; }
    });

    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            var u = input.value.trim();
            if (!u) return;
            if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(u)) u = 'https://' + u;
            location.href = u;
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) {
            e.preventDefault();
            input.focus();
            input.select();
        }
    });
})();
