document.addEventListener('DOMContentLoaded', function () {
  var toggle = document.querySelector('.mobile-menu-toggle');
  var popup = document.getElementById('mobile-nav-popup');
  if (!toggle || !popup) return;

  var closeBtn = popup.querySelector('.mobile-nav-popup-close');
  var overlay = popup.querySelector('.mobile-nav-popup-overlay');
  var links = popup.querySelectorAll('a');

  function openMenu() {
    popup.hidden = false;
    toggle.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
  }

  function closeMenu() {
    popup.hidden = true;
    toggle.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  }

  toggle.addEventListener('click', openMenu);
  if (closeBtn) closeBtn.addEventListener('click', closeMenu);
  if (overlay) overlay.addEventListener('click', closeMenu);
  for (var i = 0; i < links.length; i++) {
    links[i].addEventListener('click', closeMenu);
  }
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !popup.hidden) closeMenu();
  });
});
