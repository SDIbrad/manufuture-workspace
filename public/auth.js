// One sign-in covers every strategicdoinginitiatives.com site; it is held on the main site.
// Pages here call WORKSPACE_AUTH.signOut() from their "Sign out" link. Signing out ends the
// session for every site at once.
window.WORKSPACE_AUTH = {
  signOut: function () {
    var f = document.createElement('form');
    f.method = 'post';
    f.action = 'https://strategicdoinginitiatives.com/auth/signout';
    document.body.appendChild(f);
    f.submit();
  }
};
