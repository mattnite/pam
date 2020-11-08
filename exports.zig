const c = @cImport({
    @cInclude("security/pam_appl.h");
});

pub usingnamespace @import("src/pam.zig");
pub const intf = @import("src/intf.zig");

pub const Module = opaque {
    pub fn setData(
        self: *Module,
        comptime T: type,
        name: [:0]const u8,
        data: *T,
        cleanup: fn (*Module, *T, c_int) callconv(.C) void,
    ) !void {
        try setData(@ptrCast(*c.pam_handle_t, self), T, name, data, cleanup);
    }

    pub fn getData(
        self: *Module,
        comptime T: type,
        name: [:0]const u8,
    ) !?*T {
        return getData(@ptrCast(*c.pam_handle_t, self), T, name);
    }

    pub fn setItem(self: *Module, comptime item_type: ItemType, item: ItemType.Payload(item_type)) !void {
        try setItem(@ptrCast(*c.pam_handle_t, self), item_type, item);
    }

    pub fn getItem(self: *Module, comptime item_type: ItemType) !?*const ItemType.Payload(item_type) {
        return getItem(@ptrCast(*c.pam_handle_t, self), item_type);
    }

    pub fn getUser(self: *Module, prompt: ?[:0]const u8) ![]const u8 {
        return getUser(@ptrCast(*c.pam_handle_t, self), prompt);
    }

    pub fn putenv(self: *Module, name_value: [:0]const u8) !void {
        try putenv(@ptrCast(*c.pam_handle_t, self), name_value);
    }

    pub fn getenv(self: *Module, name: [:0]const u8) ?[]const u8 {
        return getenv(@ptrCast(*c.pam_handle_t, self), name);
    }

    pub fn getenvlist(self: *Module) ?[*:null]?[*:0]u8 {
        return getenvlist(@ptrCast(*c.pam_handle_t, self));
    }

    pub fn strerror(self: *Module, pam_error: anyerror) []const u8 {
        return strerror(@ptrCast(*c.pam_handle_t, self), errToInt(pam_error));
    }

    pub fn failDelay(self: *Module, usec: u32) !void {
        try failDelay(@ptrCast(*c.pam_handle_t, self), usec);
    }
};

pub const Client = struct {
    handle: *c.pam_handle_t,
    last_error: c_int = c.PAM_SUCCESS,

    const Self = @This();

    pub fn start(
        service_name: [:0]const u8,
        user: [:0]const u8,
        conv: *const c.pam_conv,
    ) !Self {
        return Self{
            .handle = try start(service_name, user, conv),
        };
    }

    pub fn startConfdir(
        service_name: [:0]const u8,
        user: [:0]const u8,
        conv: *c.pam_conv,
        confdir: [:0]const u8,
    ) !Self {
        return Self{
            .handle = try startConfdir(service_name, user, conv, confdir),
        };
    }

    pub fn end(self: Self) !void {
        try end(self.handle, self.last_error);
    }

    pub fn setItem(self: *Self, comptime item_type: ItemType, item: ItemType.Payload(item_type)) !void {
        setItem(self.handle, item_type, item) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn getItem(self: *Self, comptime item_type: ItemType) !?*const ItemType.Payload(item_type) {
        return getItem(self.handle, item_type) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn putenv(self: *Self, name_value: [:0]const u8) !void {
        putenv(self.handle, name_value) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn getenv(self: *Self, name) ?[]const u8 {
        return getenv(self.handle, name) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn getenvlist(self: *Self, name) ?[*:null]?[*:0]u8 {
        return getenvlist(self.handle) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn strerror(self: *Self, pam_error: anyerror) ![]const u8 {
        return strerror(self.handle, errToInt(pam_error)) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn failDelay(self: *Self, usec: u32) !void {
        failDelay(self.handle, usec) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn authenticate(self: *Self, flags: c_int) !void {
        authenticate(self.handle, flags) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn setcred(self: *Self, flags: c_int) !void {
        setcred(self.handle, flags) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn acctMgmt(self: *Self, flags: c_int) !void {
        acctMgmt(self.handle, flags) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn openSession(self: *Self, flags: c_int) !void {
        openSession(self.handle, flags) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn closeSession(self: *Self, flags: c_int) !void {
        closeSession(self.handle, flags) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }

    pub fn chauthtok(self: *Self, flags: c_int) !void {
        chauthtok(self.handle, flags) catch |err| {
            self.last_error = errToInt(err);
            return err;
        };
    }
};
