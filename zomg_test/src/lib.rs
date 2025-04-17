use windows::Win32::Foundation::{HINSTANCE, HWND};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxA;
use windows::core::s;

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        // DLL_PROCESS_DETACH => detach(),
        _ => (),
    }

    true
}

fn attach() {
    unsafe {
        // Create a message box
        MessageBoxA(
            Some(HWND(std::ptr::null_mut())),
            s!("ZOMG!"),
            s!("hello.dll"),
            Default::default(),
        );
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn go() {
    unsafe {
        // Create a message box
        MessageBoxA(
            Some(HWND(std::ptr::null_mut())),
            s!("cxaqhq"),
            s!("Rust Dll"),
            Default::default(),
        );
    };
}
