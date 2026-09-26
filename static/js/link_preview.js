// Wires up the "Safe Preview" buttons in the URL Risk Analysis table
// (templates/result.html) to the /preview-link endpoint, which runs the
// link inside TinyFish's sandboxed browser -- never the viewer's own
// browser/IP -- and shows a plain-language description of what it found.
document.addEventListener('DOMContentLoaded', function () {
  var csrfInput = document.getElementById('csrfTokenValue');
  var csrfToken = csrfInput ? csrfInput.value : '';

  document.querySelectorAll('.preview-link-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = btn.nextElementSibling;
      var url = btn.dataset.url;
      btn.disabled = true;
      target.textContent = 'Checking safely, please wait…';

      fetch('/preview-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'url=' + encodeURIComponent(url) + '&csrf_token=' + encodeURIComponent(csrfToken),
      })
        .then(function (resp) { return resp.json(); })
        .then(function (data) {
          btn.disabled = false;
          if (data.status === 'success') {
            var flag = '';
            if (data.has_login_form || data.requests_otp) {
              flag = '<span class="text-danger fw-semibold">⚠ This page asks for a password/OTP</span><br>';
            }
            target.innerHTML =
              flag +
              (data.description || '') +
              '<br><em class="text-muted">Final URL: ' + (data.final_url || url) + '</em>';
          } else if (data.status === 'not_configured') {
            target.textContent = 'Safe preview is not configured yet.';
          } else {
            target.textContent = 'Preview unavailable right now — try again shortly.';
          }
        })
        .catch(function () {
          btn.disabled = false;
          target.textContent = 'Preview unavailable right now — try again shortly.';
        });
    });
  });
});
