function checkJailbroken() {
  fn.register(24, 'getuid', [], 'bigint');
  fn.register(23, 'setuid', ['number'], 'bigint');
  var uidBefore = fn.getuid();
  var uidBeforeVal = uidBefore instanceof BigInt ? uidBefore.lo : uidBefore;
  debug('UID before setuid: ' + uidBeforeVal);
  debug('Attempting setuid(0)...');
  try {
    var setuidResult = fn.setuid(0);
    var setuidRet = setuidResult instanceof BigInt ? setuidResult.lo : setuidResult;
    debug('setuid returned: ' + setuidRet);
  } catch (e) {
    debug('setuid threw exception: ' + e.toString());
  }
  var uidAfter = fn.getuid();
  var uidAfterVal = uidAfter instanceof BigInt ? uidAfter.lo : uidAfter;
  debug('UID after setuid: ' + uidAfterVal);
  var jailbroken = uidAfterVal === 0;
  debug(jailbroken ? 'Already jailbroken' : 'Not jailbroken');
  return jailbroken;
}