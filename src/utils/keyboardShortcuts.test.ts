import assert from 'node:assert/strict';
import test from 'node:test';
import {
  GLOBAL_SHORTCUTS,
  isEditableTarget,
  matchGlobalKeyboardShortcut,
} from './keyboardShortcuts';

test('GLOBAL_SHORTCUTS documents Ctrl+K, Ctrl+I, tab jumps, and shortcut help', () => {
  const ids = GLOBAL_SHORTCUTS.map((s) => s.id);
  assert.ok(ids.includes('focus_search'));
  assert.ok(ids.includes('goto_investigate'));
  assert.ok(ids.includes('toggle_shortcuts_help'));
});

test('matchGlobalKeyboardShortcut matches Ctrl+K, Ctrl+I, Alt+1..5, /, ?, and respects editable focus guards', () => {
  const inputTarget = { tagName: 'INPUT', isContentEditable: false };
  const textareaTarget = { tagName: 'TEXTAREA', isContentEditable: false };
  const divTarget = { tagName: 'DIV', isContentEditable: false };

  assert.equal(isEditableTarget(inputTarget), true);
  assert.equal(isEditableTarget(divTarget), false);

  // Modifier shortcuts work globally even inside inputs
  assert.equal(
    matchGlobalKeyboardShortcut({ key: 'k', ctrlKey: true, target: inputTarget }),
    'focus_search',
  );
  assert.equal(
    matchGlobalKeyboardShortcut({ key: 'i', ctrlKey: true, target: textareaTarget }),
    'goto_investigate',
  );
  assert.equal(
    matchGlobalKeyboardShortcut({ key: '2', altKey: true, target: divTarget }),
    'goto_reports',
  );
  assert.equal(
    matchGlobalKeyboardShortcut({ key: 'Escape', target: textareaTarget }),
    'escape',
  );

  // Single-key shortcuts are suppressed inside editable elements
  assert.equal(matchGlobalKeyboardShortcut({ key: '/', target: inputTarget }), null);
  assert.equal(matchGlobalKeyboardShortcut({ key: '?', shiftKey: true, target: textareaTarget }), null);

  // Single-key shortcuts work outside editable elements
  assert.equal(matchGlobalKeyboardShortcut({ key: '/', target: divTarget }), 'focus_search');
  assert.equal(
    matchGlobalKeyboardShortcut({ key: '?', shiftKey: true, target: divTarget }),
    'toggle_shortcuts_help',
  );
  assert.equal(
    matchGlobalKeyboardShortcut({ key: 't', altKey: true, target: divTarget }),
    'toggle_theme',
  );
});
