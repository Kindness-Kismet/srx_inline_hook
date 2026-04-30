use super::*;

pub(super) fn run() {
    // dl_init_callback 校验 InvalidArg / Dup / Missing / Ok 的返回序
    // SAFETY: NULL+NULL 触发 InvalidArg 路径
    let dl_null_both = unsafe {
        srx_inline_hook_register_dl_init_callback(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(dl_null_both, 3, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 3);
    // SAFETY: 函数指针仅用于注册表比对，本场景不触发调用
    let dl_pre = replacement_capi_strlen as *mut c_void;
    let dl_rc = unsafe {
        srx_inline_hook_register_dl_init_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(dl_rc, 0, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 0);
    let dl_dup = unsafe {
        srx_inline_hook_register_dl_init_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(dl_dup, 36, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 36);
    let dl_unreg = unsafe {
        srx_inline_hook_unregister_dl_init_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(dl_unreg, 0, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 0);
    let dl_unreg_missing = unsafe {
        srx_inline_hook_unregister_dl_init_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(dl_unreg_missing, 37, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 37);
    let dl_unreg_null_both = unsafe {
        srx_inline_hook_unregister_dl_init_callback(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(dl_unreg_null_both, 3, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 3);
    let fini_null_both = unsafe {
        srx_inline_hook_register_dl_fini_callback(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(fini_null_both, 3, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 3);
    let fini_reg = unsafe {
        srx_inline_hook_register_dl_fini_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(fini_reg, 0, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 0);
    let fini_dup = unsafe {
        srx_inline_hook_register_dl_fini_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(fini_dup, 36, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 36);
    let fini_unreg = unsafe {
        srx_inline_hook_unregister_dl_fini_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(fini_unreg, 0, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 0);
    let fini_unreg_missing = unsafe {
        srx_inline_hook_unregister_dl_fini_callback(
            dl_pre,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(fini_unreg_missing, 37, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 37);
    let fini_unreg_null_both = unsafe {
        srx_inline_hook_unregister_dl_fini_callback(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(fini_unreg_null_both, 3, "callback_contract check failed");
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 3);

    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("#define SRX_INLINE_HOOK_STACK_SCOPE()"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("class SrxInlineHookStackScope"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("#define SRX_INLINE_HOOK_POP_STACK()"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("#define SRX_INLINE_HOOK_ALLOW_REENTRANT()"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("#define SRX_INLINE_HOOK_DISALLOW_REENTRANT()"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("#define SRX_INLINE_HOOK_RETURN_ADDRESS()"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("typedef union {")
            && SRX_INLINE_HOOK_HEADER_TEXT.contains("__uint128_t q;")
            && SRX_INLINE_HOOK_HEADER_TEXT.contains("uint32_t s[4];")
            && SRX_INLINE_HOOK_HEADER_TEXT.contains("uint16_t h[8];")
            && SRX_INLINE_HOOK_HEADER_TEXT.contains("uint8_t b[16];"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains("#define SRX_INLINE_HOOK_HOOK_RECORD           8"),
        "callback_contract check failed"
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains(
            "void *srx_inline_hook_hook_func_addr_2(void *func_addr, void *new_addr, void **orig_addr, uint32_t flags,"
        ) && SRX_INLINE_HOOK_HEADER_TEXT.contains(
            "void *srx_inline_hook_hook_sym_addr_2(void *sym_addr, void *new_addr, void **orig_addr, uint32_t flags,"
        ) && SRX_INLINE_HOOK_HEADER_TEXT.contains(
            "void *srx_inline_hook_hook_sym_name_2(const char *lib_name, const char *sym_name, void *new_addr,"
        ) && SRX_INLINE_HOOK_HEADER_TEXT.contains(
            "void *srx_inline_hook_hook_sym_name_callback_2(const char *lib_name, const char *sym_name, void *new_addr,"
        ),
        "callback_contract check failed"
    );

    // stack / reentrant：空栈下 pop / allow / disallow 均是 no-op；get_return_address 触发 abort 由 shared_stack 回归覆盖
    // SAFETY: 无副作用
    unsafe {
        srx_inline_hook_pop_stack(core::ptr::null_mut());
        srx_inline_hook_allow_reentrant(core::ptr::null_mut());
        srx_inline_hook_disallow_reentrant(core::ptr::null_mut());
    }
    println!("capi_callback_contract: PASS");
}
