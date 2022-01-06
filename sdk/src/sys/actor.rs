#[link(wasm_import_module = "actor")]
extern "C" {
    /// Resolves the ID address of an actor.
    pub fn resolve_address(addr_off: *const u8, addr_len: u32) -> super::SyscallResult2<i32, u64>;

    /// Gets the CodeCID of an actor by address.
    pub fn get_actor_code_cid(
        addr_off: *const u8,
        addr_len: u32,
        obuf_off: *mut u8,
        obuf_len: u32,
    ) -> super::SyscallResult1<i32>;

    /// Generates a new actor address for an actor deployed
    /// by the calling actor.
    pub fn new_actor_address(obuf_off: *mut u8, obuf_len: u32) -> super::SyscallResult1<u32>;

    /// Creates a new actor of the specified type in the state tree, under
    /// the provided address.
    /// TODO this syscall will change to calculate the address internally.
    pub fn create_actor(actor_id: u64, typ_off: *const u8) -> super::SyscallResult0;
}
