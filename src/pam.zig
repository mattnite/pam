const std = @import("std");
const c = @cImport({
    @cInclude("security/pam_modules.h");
});

const MessageStyle = enum(c_int) {
    prompt_echo_off,
    prompt_echo_on,
    error_msg,
    text_info,
    _,
};

const Message = extern struct {
    style: MessageStyle,
    msg: [*:0]const u8,
};

const Response = extern struct {
    resp: [*:0]const u8,
    ret_code: c_int,
};

pub fn conversation(comptime func: fn (*Allocator, []*const Message, usize) Error![]Response, appdata_ptr: usize) c.pam_conv {
    const Glue = struct {
        pub fn conv(num_msg: c_int, msg: *[*]const c.pam_message, resp: **c.pam_response, appdata_ptr: usize) callconv(.C) c_int {
            const allocator = std.heap.c_allocator;
            return blk: {
                const ret = cleanup: {
                    const response = func(allocator, msg.*[0..num_msg], appdata_ptr) catch |err| {
                        break :cleanup errToInt(err);
                    };

                    if (response.len != num_msg) {
                        allocator.free(response);
                        // TODO: is this the error we want to return?
                        break :cleanup errToInt(error.Abort);
                    }

                    break :blk 0;
                };

                var i: c_int = 0;
                while (i < num_msg) : (i += 1) {
                    allocator.destroy(msg.*[i]);
                }

                break :blk ret;
            };
        }
    };

    return c.pam_conv{
        .func = Glue.conv,
        .appdata_ptr = appdata_ptr,
    };
}

pub const DATA_REPLACE = c.PAM_DATA_REPLACE;
pub const DATA_SILENT = c.PAM_DATA_SILENT;

pub const ItemType = enum(c_int) {
    service = c.PAM_SERVICE,
    user = c.PAM_USER,
    user_prompt = c.PAM_USER_PROMPT,
    tty = c.PAM_TTY,
    ruser = c.PAM_RUSER,
    rhost = c.PAM_RHOST,
    authtok = c.PAM_AUTHTOK,
    conv = c.PAM_CONV,
    // only for linux-pam, don't use if you want to be portable
    fail_delay = c.PAM_FAIL_DELAY,
    xdisplay = c.PAM_XDISPLAY,
    xauthdata = c.PAM_AUTHDATA,
    authtok_type = c.PAM_AUTHTOK_TYPE,

    pub fn linuxPamOnly(item_type: ItemType) bool {
        return switch (item_type) {
            .fail_delay, .xdisplay, .xauthdata, .authtok_type => true,
            else => false,
        };
    }

    pub fn Payload(comptime item_type: ItemType) type {
        return switch (item_type) {
            .conv => *c.pam_conv,
            .fail_delay => fn (c_int, c_uint, usize) void,
            else => [*:0]u8,
        };
    }
};

const Error = error{
    Abort,
    AcctExpired,
    Auth,
    AuthInfoUnavail,
    AuthTok,
    AuthTokDisableAging,
    AuthTokLockBusy,
    AuthTokRecovery,
    BadItem,
    Buf,
    Conv,
    ConvAgain,
    Cred,
    CredExpired,
    CredInsufficient,
    CredUnavail,
    MaxTries,
    NewAuthtokReqd,
    PermDenied,
    System,
    TryAgain,
    UserUnknown,
};

pub fn errToInt(pam_error: Error) c_int {
    return switch (pam_error) {
        error.Abort => c.PAM_ABORT,
        error.AcctExpired => c.PAM_ACCT_EXPIRED,
        error.Auth => c.PAM_AUTH_ERR,
        error.AuthInfoUnavail => c.PAM_AUTHINFO_UNAVAIL,
        error.AuthTok => c.PAM_AUTHTOK,
        error.AuthTokDisableAging => c.PAM_AUTHTOK_DISABLE_AGING,
        error.AuthTokLockBusy => c.PAM_AUTHTOK_LOCK_BUSY,
        error.AuthTokRecovery => c.PAM_AUTHTOK_RECOVERY_ERR,
        error.BadItem => c.PAM_BAD_ITEM,
        error.Buf => c.PAM_BUF_ERR,
        error.Conv => c.PAM_CONV_ERR,
        error.ConvAgain => c.PAM_CONV_AGAIN,
        error.Cred => c.PAM_CRED_ERR,
        error.CredExpired => c.PAM_CRED_EXPIRED,
        error.CredInsufficient => c.PAM_CRED_INSUFFICIENT,
        error.CredUnavail => c.PAM_CRED_UNAVAIL,
        error.MaxTries => c.PAM_MAXTRIES,
        error.NewAuthtokReqd => c.PAM_NEW_AUTHTOK_REQD,
        error.PermDenied => c.PAM_PERM_DENIED,
        error.System => c.PAM_SYSTEM_ERR,
        error.TryAgain => c.PAM_TRY_AGAIN,
        error.UserUnknown => c.PAM_USER_UNKOWN,
        else => unreachable,
    };
}

pub fn setData(
    handle: *c.pam_handle_t,
    comptime T: type,
    name: [:0]const u8,
    data: *T,
    cleanup: fn (*c.pam_handle_t, *T, c_int) callconv(.C) void,
) !void {
    return switch (c.pam_set_data(handle, name.ptr, data, cleanup)) {
        c.PAM_SUCCESS => {},
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_SYSTEM_ERR => error.System,
        else => error.UnknownError,
    };
}

// TODO: modules _should_ treat pointer as const
pub fn getData(handle: *const c.pam_handle_t, comptime T: type, name: [:0]const u8) !?*T {
    var ret: ?*T = null;
    return switch (c.pam_get_data(@ptrCast(*const c.pam_handle_t, self), name.ptr, &ret)) {
        c.PAM_SUCCESS => ret,
        c.PAM_SYSTEM_ERR => error.System,
        c.PAM_NO_MODULE_DATA => null,
        else => error.UnknownError,
    };
}

pub fn setItem(handle: *c.pam_handle_t, comptime item_type: ItemType, item: ItemType.Payload(item_type)) !void {
    return switch (c.pam_set_item(handle, @enumToInt(item_type), item)) {
        c.PAM_SUCCESS => {},
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_BAD_ITEM => error.BadItem,
        c.PAM_SYSTEM_ERR => error.System,
        else => unreachable,
    };
}

pub fn getItem(handle: *c.pam_handle_t, comptime item_type: ItemType) !?*const ItemType.Payload(item_type) {
    var ret: ?*const ItemType.Payload(item_type) = null;
    return switch (c.pam_get_item(handle, @enumToInt(item_type), &ret)) {
        c.PAM_SUCCESS => ret,
        c.PAM_BAD_ITEM => error.BadItem,
        c.PAM_PERM_DENIED => null,
        c.PAM_SYSTEM_ERR => error.System,
        else => unreachable,
    };
}

pub fn getUser(handle: *c.pam_handle_t, prompt: ?[:0]const u8) ![]const u8 {
    var ret: [*:0]const u8 = undefined;
    return switch (c.pam_get_user(handle, &ret, if (prompt) |str| str.ptr else null)) {
        c.PAM_SUCCESS => std.mem.spanZ(ret),
        c.PAM_SYSTEM_ERR => error.System,
        c.PAM_CONV_ERR => error.Conv,
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_ABORT => error.Abort,
        c.PAM_CONV_AGAIN => error.ConvAgain,
        else => unreachable,
    };
}

pub fn putenv(handle: *c.pam_handle_t, name_value: [:0]const u8) !void {
    return switch (c.pam_putenv(handle, name_value.ptr)) {
        c.PAM_SUCCESS => {},
        c.PAM_PERM_DENIED => error.PermDenied,
        c.PAM_BAD_ITEM => error.BadItem,
        c.PAM_ABORT => error.Abort,
        c.PAM_BUF_ERR => error.Buf,
        else => unreachable,
    };
}

pub fn getenv(handle: *c.pam_handle_t, name: [:0]const u8) ?[]const u8 {
    return if (c.pam_getenv(handle, name.ptr)) |ret|
        std.mem.spanZ(ret)
    else
        null;
}

/// once this is obtained, the user must free
/// TODO: make this more typed
pub fn getenvlist(handle: *c.pam_handle_t) ?[*:null]?[*:0]u8 {
    return c.pam_getenvlist(handle);
}

pub fn strerror(handle: *c.pam_handle_t, errnum: c_int) []const u8 {
    return std.mem.spanZ(c.pam_strerror(handle, errnum));
}

pub fn failDelay(handle: *c.pam_handle_t, usec: u32) !void {
    return switch (c.pam_fail_delay(handle, @intCast(c_uint, usec))) {
        c.PAM_SUCCESS => {},
        c.PAM_SYSTEM_ERR => error.System,
        else => unreachable,
    };
}

pub fn start(
    service_name: [:0]const u8,
    user: [:0]const u8,
    conv: *const c.pam_conv,
) !*c.pam_handle_t {
    var ret: ?*c.pam_handle_t = null;
    return switch (c.pam_start(service_name.ptr, user.ptr, conv, &ret)) {
        c.PAM_SUCCESS => if (ret) |handle| handle else unreachable,
        c.PAM_ABORT => error.Abort,
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_SYSTEM_ERR => error.System,
        else => unreachable,
    };
}

pub fn startConfdir(
    service_name: [:0]const u8,
    user: [:0]const u8,
    conv: *c.pam_conv,
    confdir: [:0]const u8,
) !*c.pam_handle_t {
    var ret: ?*c.pam_handle_t = null;
    return switch (c.pam_start(service_name.ptr, user.ptr, conv, confdir.ptr, &ret)) {
        c.PAM_SUCCESS => if (ret) |handle| handle else unreachable,
        c.PAM_ABORT => error.Abort,
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_SYSTEM_ERR => error.System,
        else => unreachable,
    };
}

pub fn end(
    handle: *c.pam_handle_t,
    pam_status: c_int,
) !void {
    return switch (c.pam_end(handle, pam_status)) {
        c.PAM_SUCCESS => {},
        c.PAM_SYSTEM_ERR => error.System,
        else => unreachable,
    };
}

pub const AuthError = error{
    Auth,
    CredInsufficient,
    AuthInfoUnavail,
    UserUnknown,
    MaxTries,
};

pub fn authenticate(
    handle: *c.pam_handle_t,
    flags: c_int,
) AuthError!void {
    return switch (c.pam_authenticate(handle, flags)) {
        c.PAM_SUCCESS => {},
        c.PAM_ABORT => error.Abort,
        c.PAM_AUTH_ERR => error.Auth,
        c.PAM_CRED_INSUFFICIENT => error.CredInsufficient,
        c.PAM_AUTHINFO_UNAVAIL => error.AuthInfoUnavail,
        c.PAM_MAXTRIES => error.MaxTries,
        c.PAM_USER_UNKNOWN => error.UserUnknown,
        else => unreachable,
    };
}

pub const SetCredError = error{
    CredUnavail,
    CredExpired,
    Cred,
    UserUnknown,
};

pub fn setcred(
    handle: *c.pam_handle_t,
    flags: c_int,
) SetCredError!void {
    return switch (c.pam_setcred(handle, flags)) {
        c.PAM_SUCCESS => {},
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_CRED_ERR => error.Cred,
        c.PAM_CRED_EXPIRED => error.CredExpired,
        c.PAM_CRED_UNAVAIL => error.CredUnavail,
        c.PAM_SYSTEM_ERR => error.System,
        c.PAM_USER_UNKNOWN => error.UserUnknown,
        else => error.Unkown,
    };
}

pub const AccountError = error{
    AcctExpired,
    Auth,
    NewAuthTokReqd,
    PermDenied,
    UserUnknown,
};

pub fn acctMgmt(
    handle: *c.pam_handle_t,
    flags: c_int,
) AccountError!void {
    return switch (c.pam_acct_mgmt(handle, flags)) {
        c.PAM_SUCCESS => {},
        c.PAM_ACCT_EXPIRED => error.AcctExpired,
        c.PAM_AUTH_ERR => error.Auth,
        c.PAM_NEW_AUTHTOK_REQD => error.NewAuthtokReqd,
        c.PAM_PERM_DENIED => error.PermDenied,
        c.PAM_USER_UNKNOWN => error.UserUnknown,
        else => unreachable,
    };
}

pub const SessionError = error{Session};

pub fn openSession(
    handle: *c.pam_handle_t,
    flags: c_int,
) SessionError!void {
    return switch (c.pam_open_session(handle, flags)) {
        c.PAM_SUCCESS => {},
        c.PAM_ABORT => error.Abort,
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_SESSION_ERR => error.Session,
        else => unreachable,
    };
}

pub fn closeSession(
    handle: *c.pam_handle_t,
    flags: c_int,
) SessionError!void {
    return switch (c.pam_open_session(handle, flags)) {
        c.PAM_SUCCESS => {},
        c.PAM_ABORT => error.Abort,
        c.PAM_BUF_ERR => error.Buf,
        c.PAM_SESSION_ERR => error.Session,
        else => unreachable,
    };
}

pub const AuthTokError = error{
    AuthTok,
    AuthTokRecovery,
    AuthTokLockBusy,
    AuthTokDisableAging,
    PermDenied,
    TryAgain,
    UserUnknown,
};

pub fn chauthtok(
    handle: *c.pam_handle_t,
    flags: c_int,
) AuthTokError!void {
    return switch (c.pam_chauthtok(handle, flags)) {
        c.PAM_SUCCESS => {},
        c.PAM_AUTHTOK_ERR => error.AuthTok,
        c.PAM_AUTHTOK_RECOVERY_ERR => error.AuthTokRecovery,
        c.PAM_AUTHTOK_LOCK_BUSY => error.AuthTokLockBusy,
        c.PAM_AUTHTOK_DISABLE_AGING => error.AuthTokDisableAging,
        c.PAM_PERM_DENIED => error.PermDenied,
        c.PAM_TRY_AGAIN => error.TryAgain,
        c.PAM_USER_UNKNOWN => error.UserUnknown,
        else => unreachable,
    };
}
