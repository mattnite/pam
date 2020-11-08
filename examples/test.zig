const pam = @import("pam");
const c = @cImport({
    @cInclude("security/pam_modules.h");
});

fn authenticate(module: *pam.Module, flags: c_int, argv: []?[*:0]const u8) pam.AuthError!void {}
fn setcred(module: *pam.Module, flags: c_int, argv: []?[*:0]const u8) pam.SetCredError!void {}
fn manage(module: *pam.Module, flags: c_int, argv: []?[*:0]const u8) pam.AccountError!void {}
fn open(module: *pam.Module, flags: c_int, argv: []?[*:0]const u8) pam.SessionError!void {}
fn close(module: *pam.Module, flags: c_int, argv: []?[*:0]const u8) pam.SessionError!void {}
fn chauthtok(module: *pam.Module, flags: c_int, argv: []?[*:0]const u8) pam.AuthTokError!void {}

comptime {
    pam.intf.authentication(authenticate, setcred);
    pam.intf.account(manage);
    pam.intf.session(open, close);
    pam.intf.authtok(chauthtok);
}
