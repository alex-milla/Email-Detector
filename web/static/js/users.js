/**
 * users.js — Gestión de usuarios (Fase 2 del rediseño).
 * Sin handlers inline: delegación de eventos sobre la tabla.
 */
(function () {
  'use strict';

  var toast = window.EMD.toast;

  var createBtn = document.getElementById('createUserBtn');
  if (createBtn) createBtn.addEventListener('click', createUser);

  var table = document.getElementById('usersTable');
  if (table) table.addEventListener('click', onTableClick);

  async function createUser() {
    var username = document.getElementById('newUsername').value.trim();
    var password = document.getElementById('newPassword').value;
    var role = document.getElementById('newRole').value;
    if (!username || !password) { toast('Rellena todos los campos', 'error'); return; }

    try {
      await window.EMD.fetchJSON('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password, role: role })
      });
      toast('Usuario creado', 'success');
      setTimeout(function () { location.reload(); }, 800);
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function onTableClick(ev) {
    var btn = ev.target.closest('button[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    var id = btn.getAttribute('data-id');
    var username = btn.getAttribute('data-username');
    if (action === 'delete') deleteUser(id, username);
    else if (action === 'password') togglePasswordForm(id);
  }

  async function deleteUser(id, username) {
    if (!confirm('¿Eliminar el usuario "' + username + '"?')) return;
    try {
      await window.EMD.fetchJSON('/api/users/' + id, { method: 'DELETE' });
      var row = document.getElementById('row-' + id);
      if (row) row.remove();
      toast('Usuario eliminado', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function togglePasswordForm(id) {
    var inputId = 'pwd-input-' + id;
    var existing = document.getElementById(inputId);
    if (existing) { savePassword(id, existing); return; }

    var cell = document.querySelector('#row-' + id + ' td:last-child');
    if (!cell) return;

    var wrapper = document.createElement('div');
    wrapper.className = 'inline-edit';

    var input = document.createElement('input');
    input.type = 'password';
    input.id = inputId;
    input.className = 'input-sm';
    input.placeholder = 'Nueva contraseña';
    input.autocomplete = 'new-password';

    var save = document.createElement('button');
    save.className = 'btn btn-sm btn-primary';
    save.textContent = 'Guardar';
    save.addEventListener('click', function () { savePassword(id, input); });

    var cancel = document.createElement('button');
    cancel.className = 'btn btn-sm btn-secondary';
    cancel.textContent = 'Cancelar';
    cancel.addEventListener('click', function () { wrapper.remove(); });

    wrapper.appendChild(input);
    wrapper.appendChild(save);
    wrapper.appendChild(cancel);
    cell.appendChild(wrapper);
    input.focus();
  }

  async function savePassword(id, input) {
    var pwd = input.value;
    if (!pwd || pwd.length < 8) { toast('Mínimo 8 caracteres', 'error'); return; }
    try {
      await window.EMD.fetchJSON('/api/users/' + id + '/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd })
      });
      toast('Contraseña actualizada', 'success');
      var wrapper = input.closest('.inline-edit');
      if (wrapper) wrapper.remove();
    } catch (e) {
      toast(e.message, 'error');
    }
  }
})();
