// Punishment form field visibility, loaded as an external file so the panel
// needs no inline-script exemption in its Content-Security-Policy.
document.addEventListener('DOMContentLoaded', function () {
  var type = document.getElementById('punishType');
  var perm = document.getElementById('permField');
  var hours = document.getElementById('hoursField');
  var submit = document.getElementById('punishSubmit');
  if (!type || !perm || !hours || !submit) {
    return;
  }
  function refresh() {
    var v = type.value;
    perm.style.display = (v === 'revoke' || v === 'restore') ? '' : 'none';
    hours.style.display = (v === 'temp_ban') ? '' : 'none';
    submit.textContent = (v === 'unban') ? '确认解封'
      : (v === 'ban' ? '确认永久封禁'
        : (v === 'temp_ban' ? '确认封禁' : '确认执行'));
  }
  type.addEventListener('change', refresh);
  refresh();
});
