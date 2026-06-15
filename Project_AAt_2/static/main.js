/**
 * main.js — CryptoApp global scripts
 * Handles: password toggle, flash auto-dismiss, nav active state
 */

/* ── Password toggle ── */
function togglePassword(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.textContent = '🙈';
  } else {
    inp.type = 'password';
    btn.textContent = '👁';
  }
}

/* ── Auto-dismiss flash messages after 5 s ── */
document.addEventListener('DOMContentLoaded', () => {
  const flashes = document.querySelectorAll('.flash');
  flashes.forEach(f => {
    setTimeout(() => {
      f.style.opacity = '0';
      f.style.transition = 'opacity 0.4s ease';
      setTimeout(() => f.remove(), 400);
    }, 5000);
  });

  /* Highlight active nav link */
  const path = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(a => {
    if (a.getAttribute('href') === path) {
      a.style.color = 'var(--text-primary)';
      a.style.background = 'rgba(255,255,255,0.08)';
    }
  });
});
