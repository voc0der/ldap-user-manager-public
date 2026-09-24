/**
 * LDAP User Manager - Theme Switcher
 * Handles theme selection, persistence, and UI updates
 */

(function() {
  'use strict';

  // Get the base path from the page
  const scripts = document.getElementsByTagName('script');
  const currentScript = scripts[scripts.length - 1];
  const scriptPath = currentScript.src;
  const basePath = scriptPath.substring(0, scriptPath.lastIndexOf('/js/'));

  const THEME_API = basePath + '/api/theme.php';
  const DEFAULT_THEME = 'green-cyberpunk';

  let currentTheme = DEFAULT_THEME;
  let dropdownElement = null;
  let usernameElement = null;
  let logoutModalElement = null;
  let logoutLastFocusedElement = null;

  /**
   * Initialize the theme system
   */
  function init() {
    dropdownElement = document.getElementById('theme-dropdown');

    if (!dropdownElement) {
      console.error('Theme dropdown element not found!');
      return;
    }

    usernameElement = dropdownElement.querySelector('.username');

    // Load saved theme
    loadTheme();

    // Setup event listeners
    setupEventListeners();
  }

  /**
   * Load theme from server
   */
  function loadTheme() {
    fetch(THEME_API)
      .then(response => response.json())
      .then(data => {
        if (data.success && data.theme) {
          applyTheme(data.theme);
        }
      })
      .catch(error => {
        console.error('Failed to load theme:', error);
        applyTheme(DEFAULT_THEME);
      });
  }

  /**
   * Save theme to server
   */
  function saveTheme(theme) {
    fetch(THEME_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': window.CSRF_TOKEN || '',
      },
      body: JSON.stringify({ theme: theme }),
    })
      .then(response => response.json())
      .then(data => {
        if (!data.success) {
          console.error('Failed to save theme:', data.error);
        }
      })
      .catch(error => {
        console.error('Failed to save theme:', error);
      });
  }

  /**
   * Apply theme to document
   */
  function applyTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    updateActiveTheme();
    updateTableClasses(theme);
  }

  /**
   * Update table classes based on theme
   */
  function updateTableClasses(theme) {
    const tables = document.querySelectorAll('.table');

    tables.forEach(table => {
      if (theme === 'standard') {
        // Switch from dark to light for Standard theme
        if (table.classList.contains('table-dark')) {
          table.classList.remove('table-dark');
          table.classList.add('table-light');
          table.setAttribute('data-original-class', 'table-dark');
        }
      } else {
        // Switch back to dark for other themes
        if (table.classList.contains('table-light') && table.getAttribute('data-original-class') === 'table-dark') {
          table.classList.remove('table-light');
          table.classList.add('table-dark');
          table.removeAttribute('data-original-class');
        }
      }
    });
  }

  /**
   * Update active theme indicator in dropdown
   */
  function updateActiveTheme() {
    const themeOptions = dropdownElement.querySelectorAll('.theme-option');
    themeOptions.forEach(option => {
      if (option.getAttribute('data-theme') === currentTheme) {
        option.classList.add('active');
      } else {
        option.classList.remove('active');
      }
    });
  }

  /**
   * Resolve local/global logout URLs from dropdown data attributes
   */
  function resolveLogoutUrls() {
    const localUrl = dropdownElement.getAttribute('data-local-logout-url') ||
      dropdownElement.getAttribute('data-logout-url') || '';
    const globalUrl = dropdownElement.getAttribute('data-global-logout-url') || '';
    const hasGlobal = dropdownElement.getAttribute('data-has-global-logout') === '1' && globalUrl !== '';

    return { localUrl, globalUrl, hasGlobal };
  }

  /**
   * Only follow http(s) or site-relative URLs, never javascript: and the like.
   */
  function isSafeNavigationUrl(url) {
    return typeof url === 'string' && /^(https?:\/\/|\/)/i.test(url);
  }

  /**
   * Ensure logout modal exists in DOM
   */
  function ensureLogoutModal() {
    if (logoutModalElement) {
      return logoutModalElement;
    }

    const modal = document.createElement('div');
    modal.className = 'lum-logout-modal';
    modal.setAttribute('aria-hidden', 'true');
    modal.innerHTML = '' +
      '<div class="lum-logout-modal__backdrop" data-action="close"></div>' +
      '<div class="lum-logout-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="lum-logout-title">' +
      '  <div class="lum-logout-modal__header">' +
      '    <h3 id="lum-logout-title">Log out</h3>' +
      '    <p>Choose how far you want to sign out.</p>' +
      '  </div>' +
      '  <div class="lum-logout-modal__actions">' +
      '    <button type="button" class="btn btn-soft lum-logout-modal__choice" data-action="logout-local">User Manager only</button>' +
      '    <button type="button" class="btn btn-primary lum-logout-modal__choice" data-action="logout-global">Everything</button>' +
      '  </div>' +
      '  <div class="lum-logout-modal__footer">' +
      '    <button type="button" class="btn btn-default" data-action="cancel">Cancel</button>' +
      '  </div>' +
      '</div>';

    modal.addEventListener('click', function(e) {
      const action = e.target.getAttribute('data-action');
      if (!action) {
        return;
      }

      if (action === 'close' || action === 'cancel') {
        closeLogoutModal();
        return;
      }

      if (action === 'logout-local') {
        const localUrl = modal.getAttribute('data-local-url');
        if (isSafeNavigationUrl(localUrl)) {
          window.location.assign(localUrl);
        }
        return;
      }

      if (action === 'logout-global') {
        const globalUrl = modal.getAttribute('data-global-url');
        if (isSafeNavigationUrl(globalUrl)) {
          window.location.assign(globalUrl);
        }
      }
    });

    document.body.appendChild(modal);
    logoutModalElement = modal;
    return modal;
  }

  /**
   * Open logout confirmation modal
   */
  function openLogoutModal() {
    const modal = ensureLogoutModal();
    const urls = resolveLogoutUrls();
    const localButton = modal.querySelector('[data-action="logout-local"]');
    const globalButton = modal.querySelector('[data-action="logout-global"]');

    modal.setAttribute('data-local-url', urls.localUrl);
    modal.setAttribute('data-global-url', urls.hasGlobal ? urls.globalUrl : '');

    if (urls.localUrl === '') {
      localButton.setAttribute('disabled', 'disabled');
    } else {
      localButton.removeAttribute('disabled');
    }

    if (!urls.hasGlobal) {
      globalButton.setAttribute('disabled', 'disabled');
      globalButton.textContent = 'Everything (Unavailable)';
    } else {
      globalButton.removeAttribute('disabled');
      globalButton.textContent = 'Everything';
    }

    logoutLastFocusedElement = document.activeElement;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('lum-logout-open');
    window.setTimeout(function() {
      if (urls.localUrl !== '') {
        localButton.focus();
      } else {
        const cancelButton = modal.querySelector('[data-action="cancel"]');
        if (cancelButton) {
          cancelButton.focus();
        }
      }
    }, 0);
  }

  /**
   * Close logout confirmation modal
   */
  function closeLogoutModal() {
    if (!logoutModalElement) {
      return;
    }

    logoutModalElement.classList.remove('is-open');
    logoutModalElement.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('lum-logout-open');
    if (logoutLastFocusedElement && typeof logoutLastFocusedElement.focus === 'function') {
      logoutLastFocusedElement.focus();
    }
    logoutLastFocusedElement = null;
  }

  function isLogoutModalOpen() {
    return !!(logoutModalElement && logoutModalElement.classList.contains('is-open'));
  }

  /**
   * Setup event listeners
   */
  function setupEventListeners() {
    // Toggle dropdown on username click
    usernameElement.addEventListener('click', function(e) {
      e.stopPropagation();
      toggleDropdown();
    });

    // Handle theme selection
    const themeOptions = dropdownElement.querySelectorAll('.theme-option[data-theme]');
    themeOptions.forEach(option => {
      option.addEventListener('click', function(e) {
        e.stopPropagation();
        const selectedTheme = this.getAttribute('data-theme');
        if (selectedTheme && selectedTheme !== currentTheme) {
          applyTheme(selectedTheme);
          saveTheme(selectedTheme);
        }
        closeDropdown();
      });
    });

    const logoutOption = dropdownElement.querySelector('[data-action="logout"]');
    if (logoutOption) {
      const triggerLogout = function(e) {
        e.preventDefault();
        e.stopPropagation();
        closeDropdown();
        openLogoutModal();
      };

      logoutOption.addEventListener('click', triggerLogout);
      logoutOption.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          triggerLogout(e);
        }
      });
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
      if (!dropdownElement.contains(e.target)) {
        closeDropdown();
      }
    });

    // Close dropdown or modal on escape key
    document.addEventListener('keydown', function(e) {
      if (e.key !== 'Escape') {
        return;
      }

      if (isLogoutModalOpen()) {
        e.preventDefault();
        closeLogoutModal();
        return;
      }
      closeDropdown();
    });
  }

  /**
   * Toggle dropdown open/closed
   */
  function toggleDropdown() {
    if (dropdownElement.classList.contains('open')) {
      closeDropdown();
    } else {
      openDropdown();
    }
  }

  /**
   * Open dropdown
   */
  function openDropdown() {
    dropdownElement.classList.add('open');
  }

  /**
   * Close dropdown
   */
  function closeDropdown() {
    dropdownElement.classList.remove('open');
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
