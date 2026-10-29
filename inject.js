// SNI Browser — injected keyboard shortcuts & floating URL bar
(function(){
    if (window.__sni_injected) return;
    window.__sni_injected = true;

    // ---- Floating URL bar (appears on Ctrl+L / click at top) ----
    var bar = document.createElement('div');
    bar.id = '__sni_bar';
    bar.innerHTML = '<input id="__sni_url_input" type="text" placeholder="https://...">' +
        '<span id="__sni_sni_status" title="All HTTPS traffic is SNI-spoofed through local proxy">🔒 SNI</span>';
    // Inline critical CSS so the bar renders before external CSS loads.
    bar.setAttribute('style',
        'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;'+
        'height:36px;background:#1a1a2e;color:#ccc;display:none;align-items:center;'+
        'padding:0 8px;gap:6px;font:13px sans-serif;box-shadow:0 2px 12px rgba(0,0,0,.5)');
    document.documentElement.appendChild(bar);

    var input = document.getElementById('__sni_url_input');
    input.setAttribute('style',
        'flex:1;height:26px;background:rgba(255,255,255,.06);'+
        'border:1px solid rgba(255,255,255,.15);border-radius:13px;'+
        'color:#e0e0e0;padding:0 12px;font:13px sans-serif;outline:none');
    var status = document.getElementById('__sni_sni_status');
    status.setAttribute('style','font:11px sans-serif;color:#4f8;white-space:nowrap;padding:0 6px');

    input.addEventListener('keydown', function(e){
        if (e.key === 'Enter') {
            var url = input.value.trim();
            if (url) { try { navigateTo(url); } catch(err) { window.location.href = url; } }
            bar.style.display = 'none';
        }
        if (e.key === 'Escape') {
            bar.style.display = 'none';
        }
    });

    function showBar(){
        bar.style.display = 'flex';
        input.value = window.location.href;
        input.focus();
        input.select();
    }

    // ---- Keyboard shortcuts ----
    document.addEventListener('keydown', function(e){
        // Ctrl+L: open URL bar
        if (e.ctrlKey && e.key === 'l') {
            e.preventDefault();
            showBar();
        }
        // Alt+Left: back
        if (e.altKey && e.key === 'ArrowLeft') {
            e.preventDefault();
            try { window.history.back(); } catch(_) {}
        }
        // Alt+Right: forward
        if (e.altKey && e.key === 'ArrowRight') {
            e.preventDefault();
            try { window.history.forward(); } catch(_) {}
        }
        // F5: refresh
        if (e.key === 'F5') {
            e.preventDefault();
            try { window.location.reload(); } catch(_) {}
        }
        // Ctrl+R: refresh
        if (e.ctrlKey && e.key === 'r') {
            e.preventDefault();
            try { window.location.reload(); } catch(_) {}
        }
    });

    // ---- Report URL to title bar ----
    function updateTitle(){
        try { reportURL(window.location.href); } catch(_) {}
    }
    updateTitle();
    window.addEventListener('popstate', updateTitle);
    window.addEventListener('hashchange', updateTitle);

    // Poll for pushState changes.
    var last = window.location.href;
    setInterval(function(){
        if (window.location.href !== last) { last = window.location.href; updateTitle(); }
    }, 500);
})();