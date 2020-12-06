const pam = @import("main.zig");
const c = @cImport({
    @cInclude("security/pam_modules.h");
});

pub fn authentication(
    comptime authenticate: fn (*pam.Module, c_int, []?[*:0]const u8) pam.AuthError!void,
    comptime setcred: fn (*pam.Module, c_int, []?[*:0]const u8) pam.SetCredError!void,
) comptime void {
    const Glue = struct {
        pub fn authenticate(
            handle: *c.pam_handle_t,
            flags: c_int,
            argc: c_int,
            argv: [*]?[*:0]const u8,
        ) callconv(.C) c_int {
            authenticate(@ptrCast(*pam.Module, handle), flags, argv[0..@intCast(usize, argc)]) catch |err| {
                return switch (err) {
                    error.Auth => c.PAM_AUTH_ERR,
                    error.CredInsufficient => c.PAM_CRED_INSUFFICIENT,
                    error.AuthInfoUnavail => c.PAM_AUTHINFO_UNAVAIL,
                    error.UserUnknown => c.PAM_USER_UNKNOWN,
                    error.MaxTries => c.PAM_MAXTRIES,
                };
            };

            return c.PAM_SUCCESS;
        }

        pub fn setcred(
            handle: *c.pam_handle_t,
            flags: c_int,
            argc: c_int,
            argv: [*]?[*:0]const u8,
        ) callconv(.C) c_int {
            setcred(@ptrCast(*pam.Module, handle), flags, argv[0..@intCast(usize, argc)]) catch |err| {
                return switch (err) {
                    error.CredUnavail => c.PAM_CRED_UNAVAIL,
                    error.CredExpired => c.PAM_CRED_EXPIRED,
                    error.Cred => c.PAM_CRED_ERR,
                    error.UserUnknown => c.PAM_USER_UNKNOWN,
                };
            };

            return c.PAM_SUCCESS;
        }
    };

    @export(Glue.authenticate, .{ .name = "pam_sm_authenticate", .linkage = .Strong });
    @export(Glue.setcred, .{ .name = "pam_sm_setcred", .linkage = .Strong });
}

pub fn account(
    comptime manage: fn (*pam.Module, c_int, []?[*:0]const u8) pam.AccountError!void,
) comptime void {
    const Glue = struct {
        pub fn manage(
            handle: *c.pam_handle_t,
            flags: c_int,
            argc: c_int,
            argv: [*]?[*:0]const u8,
        ) callconv(.C) c_int {
            manage(@ptrCast(*pam.Module, handle), flags, argv[0..@intCast(usize, argc)]) catch |err| {
                return switch (err) {
                    error.AcctExpired => c.PAM_ACCT_EXPIRED,
                    error.Auth => c.PAM_AUTH_ERR,
                    error.NewAuthTokReqd => c.PAM_NEW_AUTHTOK_REQD,
                    error.PermDenied => c.PAM_PERM_DENIED,
                    error.UserUnknown => c.PAM_USER_UNKNOWN,
                };
            };

            return c.PAM_SUCCESS;
        }
    };

    @export(Glue.manage, .{ .name = "pam_sm_acct_mgmt", .linkage = .Strong });
}

pub fn session(
    comptime open: fn (*pam.Module, c_int, []?[*:0]const u8) pam.SessionError!void,
    comptime close: fn (*pam.Module, c_int, []?[*:0]const u8) pam.SessionError!void,
) comptime void {
    const Glue = struct {
        pub fn open(
            handle: *c.pam_handle_t,
            flags: c_int,
            argc: c_int,
            argv: [*]?[*:0]const u8,
        ) callconv(.C) c_int {
            open(@ptrCast(*pam.Module, handle), flags, argv[0..@intCast(usize, argc)]) catch |err| {
                return switch (err) {
                    error.Session => c.PAM_SESSION_ERR,
                };
            };

            return c.PAM_SUCCESS;
        }

        pub fn close(
            handle: *c.pam_handle_t,
            flags: c_int,
            argc: c_int,
            argv: [*]?[*:0]const u8,
        ) callconv(.C) c_int {
            close(@ptrCast(*pam.Module, handle), flags, argv[0..@intCast(usize, argc)]) catch |err| {
                return switch (err) {
                    error.Session => c.PAM_SESSION_ERR,
                };
            };

            return c.PAM_SUCCESS;
        }
    };

    @export(Glue.open, .{ .name = "pam_sm_open_session", .linkage = .Strong });
    @export(Glue.close, .{ .name = "pam_sm_close_session", .linkage = .Strong });
}

pub fn authtok(
    comptime chauthtok: fn (*pam.Module, c_int, []?[*:0]const u8) pam.AuthTokError!void,
) comptime void {
    const Glue = struct {
        pub fn chauthtok(
            handle: *c.pam_handle_t,
            flags: c_int,
            argc: c_int,
            argv: [*]?[*:0]const u8,
        ) callconv(.C) c_int {
            chauthtok(@ptrCast(*pam.Module, handle), flags, argv[0..@intCast(usize, argc)]) catch |err| {
                return switch (err) {
                    error.AuthTok => c.PAM_AUTHTOK_ERR,
                    error.AuthTokRecovery => c.PAM_AUTHTOK_RECOVERY_ERR,
                    error.AuthTokLockBusy => c.PAM_AUTHTOK_LOCK_BUSY,
                    error.AuthTokDisableAging => c.PAM_AUTHTOK_DISABLE_AGING,
                    error.PermDenied => c.PAM_PERM_DENIED,
                    error.TryAgain => c.PAM_TRY_AGAIN,
                    error.UserUnknown => c.PAM_USER_UNKNOWN,
                };
            };

            return c.PAM_SUCCESS;
        }
    };

    @export(Glue.chauthtok, .{ .name = "pam_sm_chauthtok", .linkage = .Strong });
}
