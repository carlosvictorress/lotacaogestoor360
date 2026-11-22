/**
 * Proteção CSRF Automática — Gestoor 360
 * Injeta o token CSRF em todos os formulários POST e requisições fetch/XHR da mesma origem.
 */
(function () {
    function getCsrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : '';
    }

    function injectFormTokens(root) {
        const token = getCsrfToken();
        if (!token) return;
        const forms = (root || document).querySelectorAll('form');
        forms.forEach(function (form) {
            const method = (form.getAttribute('method') || 'GET').toUpperCase();
            if (method === 'POST') {
                let input = form.querySelector('input[name="csrf_token"]');
                if (!input) {
                    input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'csrf_token';
                    form.appendChild(input);
                }
                input.value = token;
            }
        });
    }

    // Patch fetch() para enviar X-CSRF-Token em requisições mutáveis da mesma origem
    if (window.fetch) {
        const origFetch = window.fetch;
        window.fetch = function (input, init) {
            const opts = init ? Object.assign({}, init) : {};
            const method = (opts.method || 'GET').toUpperCase();
            if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
                const urlStr = typeof input === 'string' ? input : (input && input.url) || '';
                const isSameOrigin = !urlStr || urlStr.startsWith('/') || urlStr.startsWith(window.location.origin);
                if (isSameOrigin) {
                    const token = getCsrfToken();
                    if (token) {
                        const headers = new Headers(opts.headers || {});
                        if (!headers.has('X-CSRF-Token')) {
                            headers.set('X-CSRF-Token', token);
                        }
                        opts.headers = headers;
                    }
                }
            }
            return origFetch.call(this, input, opts);
        };
    }

    // Patch XMLHttpRequest (jQuery AJAX, etc.)
    if (window.XMLHttpRequest) {
        const origOpen = XMLHttpRequest.prototype.open;
        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function (method, url) {
            this._g360Method = (method || 'GET').toUpperCase();
            this._g360Url = url || '';
            return origOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function () {
            if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(this._g360Method)) {
                const isSameOrigin = !this._g360Url || this._g360Url.startsWith('/') || this._g360Url.startsWith(window.location.origin);
                const token = getCsrfToken();
                if (isSameOrigin && token) {
                    try {
                        this.setRequestHeader('X-CSRF-Token', token);
                    } catch (e) {}
                }
            }
            return origSend.apply(this, arguments);
        };
    }

    document.addEventListener('DOMContentLoaded', function () {
        injectFormTokens(document);
        // Observa formulários inseridos dinamicamente (modais)
        if (window.MutationObserver && document.body) {
            const obs = new MutationObserver(function () {
                injectFormTokens(document);
            });
            obs.observe(document.body, { childList: true, subtree: true });
        }
    });
})();
