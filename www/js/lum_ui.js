// Small shared UI helpers used by the inline page scripts (replaces jQuery).
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  // Fade an element out, collapse it, then remove it.
  function dismiss(el, ms) {
    if (!el || el.dataset.lumDismissing) {
      return;
    }
    el.dataset.lumDismissing = '1';
    const duration = typeof ms === 'number' ? ms : 300;
    if (typeof el.animate !== 'function') {
      el.remove();
      return;
    }
    const style = window.getComputedStyle(el);
    const fade = el.animate([{ opacity: style.opacity }, { opacity: 0 }], { duration: duration, fill: 'forwards' });
    fade.onfinish = function () {
      el.style.overflow = 'hidden';
      const slide = el.animate([
        {
          height: el.offsetHeight + 'px',
          paddingTop: style.paddingTop,
          paddingBottom: style.paddingBottom,
          marginTop: style.marginTop,
          marginBottom: style.marginBottom,
        },
        { height: '0px', paddingTop: '0px', paddingBottom: '0px', marginTop: '0px', marginBottom: '0px' },
      ], { duration: duration, fill: 'forwards' });
      slide.onfinish = function () {
        el.remove();
      };
    };
  }

  // Show only the rows whose text contains what's typed into the input.
  function bindRowFilter(inputSelector, rowSelector) {
    const input = document.querySelector(inputSelector);
    if (!input) {
      return;
    }
    const apply = function () {
      const needle = input.value.toLowerCase();
      document.querySelectorAll(rowSelector).forEach(function (row) {
        row.style.display = row.textContent.toLowerCase().indexOf(needle) > -1 ? '' : 'none';
      });
    };
    input.addEventListener('input', apply);
    input.addEventListener('keyup', apply);
  }

  // Two-column picker: .list-left / .list-right panels, .list-arrows move
  // buttons, a .selector "select all" per panel and a SearchDualList filter.
  // onMove runs after every move-button click.
  function initDualList(onMove) {
    document.body.addEventListener('click', function (e) {
      const item = e.target.closest('.list-group .list-group-item');
      if (item) {
        item.classList.toggle('active');
      }
    });

    document.querySelectorAll('.list-arrows button').forEach(function (button) {
      button.addEventListener('click', function () {
        let from = null;
        let to = null;
        if (button.classList.contains('move-left')) {
          from = '.list-right ul';
          to = '.list-left ul';
        } else if (button.classList.contains('move-right')) {
          from = '.list-left ul';
          to = '.list-right ul';
        }
        const target = to ? document.querySelector(to) : null;
        if (target) {
          document.querySelectorAll(from + ' li.active').forEach(function (li) {
            li.classList.remove('active');
            target.appendChild(li);
          });
        }
        if (onMove) {
          onMove();
        }
      });
    });

    document.querySelectorAll('.dual-list .selector').forEach(function (selector) {
      selector.addEventListener('click', function () {
        const selectAll = !selector.classList.contains('selected');
        selector.classList.toggle('selected', selectAll);
        const well = selector.closest('.well');
        if (well) {
          well.querySelectorAll('ul li').forEach(function (li) {
            li.classList.toggle('active', selectAll);
          });
        }
        const icon = selector.querySelector(':scope > i');
        if (icon) {
          icon.textContent = selectAll ? '☑' : '☐';
        }
      });
    });

    document.querySelectorAll('[name="SearchDualList"]').forEach(function (input) {
      input.addEventListener('keyup', function (e) {
        if (e.key === 'Tab') {
          return;
        }
        if (e.key === 'Escape') {
          input.value = '';
        }
        const panel = input.closest('.dual-list');
        if (!panel) {
          return;
        }
        const needle = input.value.trim().replace(/ +/g, ' ').toLowerCase();
        panel.querySelectorAll('.list-group li').forEach(function (li) {
          const text = li.textContent.replace(/\s+/g, ' ').toLowerCase();
          li.style.display = text.indexOf(needle) === -1 ? 'none' : '';
        });
      });
    });
  }

  window.lumUI = {
    ready: ready,
    dismiss: dismiss,
    bindRowFilter: bindRowFilter,
    initDualList: initDualList,
  };
})();
