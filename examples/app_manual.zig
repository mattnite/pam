const pam = @import("linux-pam");

const conv = pam.Conversation{
    .conv = some_func,
    .appdata_ptr = 0,
};

pub fn main() !void {
    const client = try pam.Client.start("check_user", "mknight", &conv);
    defer client.end();

    try client.authenticate(0);
    try client.acctMgmt(0);
}
