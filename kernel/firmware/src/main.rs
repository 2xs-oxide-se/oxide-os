#![no_std]
#![no_main]

extern crate alloc;
#[cfg(test)]
extern crate std;
#[cfg(test)]
use std::prelude::rust_2021::*;

use crate::apdu_layer::{ApduLayer, PassthroughApduLayer, TracingApduLayer};
use crate::secure_channel::SecureChannelLayer;
use rustlet_runtime::SEApdu;

mod apdu_debug_mod;
mod apdu_layer;
mod apdu_manager;
mod atr;
mod embedded_apps;
mod fae_runtime;
mod gp_status;
mod kernel_main_app;
mod object_registry;
#[allow(dead_code)]
mod object_registry_persistence;
mod predeployment;
mod secure_channel;
mod security_domain;
mod selected_app;
mod time_manager;
mod transport_layer;

pub use oxi_core::core;

// A kernel-only image routes every command to its statically selected kernel
// modules. It contains neither predeployed Rustlets nor GlobalPlatform command
// dispatch.
const KERNEL_ONLY_IMAGE: bool = cfg!(oxide_se_kernel_image_kernel_only);

static mut MANAGEMENT_PAYLOAD_SCRATCH: [u8; rustlet_runtime::APDU_BUFFER_CAPACITY] =
    [0; rustlet_runtime::APDU_BUFFER_CAPACITY];

#[derive(Clone, Copy)]
struct GetStatusCursor {
    authority_aid: rustlet_runtime::Aid,
    query: gp_status::GetStatusQuery,
    next_slot: usize,
}

static mut GET_STATUS_CURSOR: Option<GetStatusCursor> = None;

fn get_status_cursor() -> Option<GetStatusCursor> {
    unsafe { ::core::ptr::read_volatile(::core::ptr::addr_of!(GET_STATUS_CURSOR)) }
}

fn set_get_status_cursor(cursor: Option<GetStatusCursor>) {
    unsafe {
        ::core::ptr::write_volatile(::core::ptr::addr_of_mut!(GET_STATUS_CURSOR), cursor);
    }
}

fn stage_management_payload(payload: &[u8]) -> Option<&'static [u8]> {
    if payload.len() > rustlet_runtime::APDU_PAYLOAD_LENGTH_MAX {
        return None;
    }
    // Invariant: the APDU loop is single-threaded. This scratch keeps
    // management payloads stable across RustletSD authorization hooks, which
    // republish the shared APDU buffer for SDDISPATCH.
    let scratch = unsafe { &mut *::core::ptr::addr_of_mut!(MANAGEMENT_PAYLOAD_SCRATCH) };
    scratch[..payload.len()].copy_from_slice(payload);
    Some(&scratch[..payload.len()])
}

fn kernel_main() -> i32 {
    let execution_env = core::target::execution_env();
    let scripted_transport_mode =
        execution_env == "simulate_apdu" || execution_env == "simulate_apdu_scp11c";
    let scripted_kernel_main_app_mode = execution_env == "simulate_apdu";
    let transport = transport_layer::current_transport();
    let t0_manager = apdu_manager::T0ApduManager::new(transport);
    let passthrough_layer = PassthroughApduLayer::new(t0_manager);
    let secure_channel_layer = SecureChannelLayer::new(passthrough_layer);
    let mut apdu_layer = TracingApduLayer::new(secure_channel_layer, scripted_transport_mode);
    kernel_main_with_layer(
        &mut apdu_layer,
        scripted_transport_mode,
        scripted_kernel_main_app_mode,
    )
}

fn kernel_main_with_layer(
    apdu_manager: &mut impl ApduLayer,
    scripted_transport_mode: bool,
    scripted_kernel_main_app_mode: bool,
) -> i32 {
    // ISO/IEC 7816-3 budgets the reset-to-ATR path tightly. We are expected
    // to have finished boot/runtime initialization before reaching this point.
    if scripted_transport_mode {
        apdu_debug_mod::initialize();
    } else {
        let historical_bytes = atr::historical_bytes();
        apdu_manager.send_atr(&historical_bytes);
    }

    loop {
        if scripted_transport_mode && !apdu_debug_mod::prepare_next_command() {
            return 0;
        }

        // Hot path: do not insert unrelated work between ATR/status emission
        // and the next command reception. The transport may continue with only
        // the normal ETU/guard-time budget between frames.
        let Some(mut command) = apdu_manager.receive_command() else {
            continue;
        };

        // Hot path: once the 5-byte header is available, hand control to the
        // APDU handler immediately. The handler may decide that incoming data
        // must be received right away, so avoid interposing logging, scans,
        // allocation, or other unrelated work here.
        let status = {
            let is_select_apdu = is_select(&command);
            let is_install_apdu = is_install(&command);
            let is_get_data_apdu = is_get_data(&command);
            let is_get_status_apdu = is_get_status(&command);
            let is_put_key_apdu = is_put_key(&command);
            let is_store_data_apdu = is_store_data(&command);
            let is_delete_apdu = is_delete(&command);
            let is_load_apdu = is_load(&command);
            let is_set_status_apdu = is_set_status(&command);
            let is_install_for_load_apdu =
                is_install_apdu && command.p1() == 0x02 && command.p2() == 0x00;
            if selected_app::dynamic_package_load_in_progress()
                && !is_load_apdu
                && !is_install_for_load_apdu
            {
                selected_app::cancel_dynamic_package_load();
            }
            if !is_get_status_apdu {
                set_get_status_cursor(None);
            }
            let mut apdu = command.as_apdu();
            if let Some(status) = kernel_main_app::filter_apdu(&mut apdu) {
                status
            } else if KERNEL_ONLY_IMAGE || scripted_kernel_main_app_mode {
                apdu_manager::ApduStatus::instruction_not_supported()
            } else if is_get_data_apdu {
                handle_get_data(&mut apdu)
            } else if is_get_status_apdu {
                handle_get_status(&mut apdu)
            } else if is_put_key_apdu {
                handle_put_key(&mut apdu)
            } else if is_store_data_apdu {
                handle_store_data(&mut apdu)
            } else if is_delete_apdu {
                handle_delete(&mut apdu)
            } else if is_load_apdu {
                handle_load(&mut apdu)
            } else if is_set_status_apdu {
                handle_set_status(&mut apdu)
            } else if is_select_apdu {
                handle_select(&mut apdu)
            } else if is_install_apdu {
                handle_install(&mut apdu)
            } else {
                selected_app::dispatch(&mut apdu)
            }
        };

        apdu_manager.complete_command(command.complete(status));

        kernel_main_app::after_apdu();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    core::kernel_stack_overflow_protection();

    core::initialize();
    time_manager::initialize();
    kernel_main_app::initialize();
    selected_app::initialize();
    let exit_code = kernel_main();
    core::shutdown(exit_code)
}

struct GpInstallCommand<'a> {
    package_aid: rustlet_runtime::Aid,
    applet_aid: rustlet_runtime::Aid,
    instance_aid: rustlet_runtime::Aid,
    privileges: &'a [u8],
    install_parameters: &'a [u8],
}

struct GpInstallForLoadCommand<'a> {
    package_aid: rustlet_runtime::Aid,
    security_domain_aid: rustlet_runtime::Aid,
    load_file_hash: &'a [u8],
    load_parameters: &'a [u8],
    load_token: &'a [u8],
}

fn selected_kernel_side_security_domain_kind() -> Option<selected_app::SecurityDomainObjectBackend>
{
    match crate::predeployment::root_backend() {
        crate::predeployment::RootSecurityDomainBackend::NullSecurityDomain => {
            Some(selected_app::SecurityDomainObjectBackend::NullSecurityDomain)
        }
        crate::predeployment::RootSecurityDomainBackend::KernelSecurityDomain => {
            Some(selected_app::SecurityDomainObjectBackend::KernelSecurityDomain)
        }
        crate::predeployment::RootSecurityDomainBackend::RustletSecurityDomainProxy => None,
    }
}

fn is_select(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    apdu.ins() == rustlet_runtime::INS_SELECT
}

fn is_install(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    apdu.ins() == rustlet_runtime::INS_INSTALL
}

fn is_get_data(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    (apdu.cla() == 0x80 || apdu.cla() == 0x84) && apdu.ins() == 0xca
}

fn is_get_status(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    (apdu.cla() == 0x80 || apdu.cla() == 0x84) && apdu.ins() == 0xf2
}

fn is_put_key(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    (apdu.cla() == 0x80 || apdu.cla() == 0x84) && apdu.ins() == 0xd8
}

fn is_store_data(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    (apdu.cla() == 0x80 || apdu.cla() == 0x84) && apdu.ins() == 0xe2
}

fn is_delete(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    (apdu.cla() == 0x80 || apdu.cla() == 0x84) && apdu.ins() == 0xe4
}

fn is_set_status(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    (apdu.cla() == 0x80 || apdu.cla() == 0x84) && apdu.ins() == 0xf0
}

fn is_load(apdu: &crate::apdu_layer::ApduCommand) -> bool {
    (apdu.cla() == 0x80 || apdu.cla() == 0x84) && apdu.ins() == 0xe8
}

fn is_secure_messaging_command_cla(cla: u8) -> bool {
    (cla & 0x04) != 0
}

fn management_authority_aid_for_cla(cla: u8) -> rustlet_runtime::Aid {
    if is_secure_messaging_command_cla(cla) {
        selected_app::active_security_domain_instance_aid()
    } else {
        security_domain::root_security_domain_aid()
    }
}

fn authorize_management_operation(
    cla: u8,
    operation: security_domain::ManagementOperation,
    target: security_domain::ManagementTarget,
) -> Result<rustlet_runtime::Aid, apdu_manager::ApduStatus> {
    let addressed_authority_aid = management_authority_aid_for_cla(cla);
    let adapted = security_domain::adapt_management_apdu(
        operation,
        addressed_authority_aid,
        security_domain::root_security_domain_aid(),
    );
    // The APDU adapter is the only place that recognizes Global Delete,
    // Global Lock (SET STATUS), and Global Registry (GET STATUS). Their
    // handlers below receive the same operation and the same authority
    // parameter as ordinary subtree operations.
    let authority_aid = adapted.authority_aid;
    if !is_secure_messaging_command_cla(cla)
        && matches!(
            operation,
            security_domain::ManagementOperation::GetData
                | security_domain::ManagementOperation::GetStatus
        )
    {
        // Clear reads are refined by the backend's registry-plane policy in
        // handle_get_data; avoid loading the authority twice on this hot path.
        return Ok(authority_aid);
    }
    let allowed =
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            if is_secure_messaging_command_cla(cla) {
                return security_domain::active_secure_channel_allows_management(operation, target);
            }
            match operation {
                security_domain::ManagementOperation::GetData
                | security_domain::ManagementOperation::GetStatus => true,
                security_domain::ManagementOperation::SetStatus => {
                    security_domain.permits_set_status_without_secure_channel()
                }
                _ => security_domain.permits_management_without_secure_channel(),
            }
        });
    if allowed {
        Ok(authority_aid)
    } else {
        Err(apdu_manager::ApduStatus::conditions_not_satisfied())
    }
}

fn management_target_for_aid(aid: &rustlet_runtime::Aid) -> security_domain::ManagementTarget {
    if matches!(
        selected_app::find_managed_object_kind_by_aid(aid),
        Some(selected_app::ManagedObjectKind::Key)
    ) || (aid.len == 6 && aid.bytes[..3] == [0x4B, 0x45, 0x59])
    {
        security_domain::ManagementTarget::Key
    } else {
        security_domain::ManagementTarget::Object
    }
}

fn handle_select(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    let aid = &apdu.incoming_data()[..incoming_len];
    let target_aid = rustlet_runtime::Aid::new(aid);
    let target_kind = selected_app::find_managed_object_kind_by_aid(&target_aid);
    let status = selected_app::select_aid(aid);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return status;
    }

    if matches!(
        target_kind,
        Some(selected_app::ManagedObjectKind::SecurityDomain)
    ) {
        let rustlet_security_domain = matches!(
            selected_app::security_domain_backend_by_aid(&target_aid),
            Some(selected_app::SecurityDomainObjectBackend::RustletSecurityDomain)
        );
        if !rustlet_security_domain {
            return apdu_manager::ApduStatus::success();
        }
        let dispatch_status = selected_app::dispatch_select(apdu);
        if dispatch_status.sw1 == 0x90 && dispatch_status.sw2 == 0x00 {
            selected_app::promote_selected_app_to_security_domain();
        }
        return dispatch_status;
    }

    selected_app::dispatch_select(apdu)
}

fn handle_install(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    if header.p1 == 0x02 && header.p2 == 0x00 {
        return handle_install_for_load(apdu);
    }
    if header.p1 != 0x0c || header.p2 != 0x00 {
        return apdu_manager::ApduStatus::wrong_data();
    }

    let incoming_len = apdu.set_incoming_and_receive();
    let Some(incoming) = stage_management_payload(&apdu.incoming_data()[..incoming_len]) else {
        return apdu_manager::ApduStatus::wrong_length();
    };
    let command = match parse_gp_install_command(incoming) {
        Some(command) => command,
        None => return apdu_manager::ApduStatus::wrong_data(),
    };

    if command.package_aid.len == 0 || command.applet_aid.len == 0 || command.instance_aid.len == 0
    {
        return apdu_manager::ApduStatus::wrong_data();
    }
    if command.privileges.len() > 3 {
        return apdu_manager::ApduStatus::wrong_data();
    }

    let install_command = security_domain::InstallForInstallCommand {
        package_aid: command.package_aid,
        applet_aid: command.applet_aid,
        instance_aid: command.instance_aid,
        privileges: command.privileges,
        install_parameters: command.install_parameters,
    };
    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::InstallForInstall,
        security_domain::ManagementTarget::Object,
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    let install_status =
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            if !security_domain.may_manage_security_domain_plane()
                || !security_domain.may_access_registry_plane()
                || !security_domain.may_manage_applet(
                    &command.package_aid,
                    &command.applet_aid,
                    &command.instance_aid,
                )
                || !security_domain.may_make_selectable(&command.instance_aid)
            {
                return Some(apdu_manager::ApduStatus::conditions_not_satisfied());
            }
            management_result_to_status(security_domain.install_for_install(&install_command))
        });
    if let Some(status) = install_status {
        return status;
    }

    if let Some(object_kind) = selected_kernel_side_security_domain_kind() {
        let root_package_aid = crate::predeployment::root_package_aid();
        if command.package_aid == root_package_aid && command.applet_aid == root_package_aid {
            return selected_app::install_kernel_side_security_domain_instance(
                object_kind,
                authority_aid,
                command.package_aid,
                command.instance_aid,
                command.privileges,
            );
        }
    }

    apdu.buffer_mut()[..incoming_len].copy_from_slice(incoming);
    let status = selected_app::install_instance_in_security_domain_from_current_apdu(
        &authority_aid,
        &command.package_aid,
        &command.applet_aid,
        &command.instance_aid,
        command.privileges,
        command.install_parameters,
        rustlet_runtime::RustletApduHeader {
            cla: header.cla,
            ins: header.ins,
            p1: header.p1,
            p2: header.p2,
            lc: header.p3,
            le: header.p3,
        },
        incoming_len,
    );
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return status;
    }
    status
}

fn handle_install_for_load(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    let incoming_len = apdu.set_incoming_and_receive();
    let command = match parse_gp_install_for_load_command(&apdu.incoming_data()[..incoming_len]) {
        Some(command) => command,
        None => return apdu_manager::ApduStatus::wrong_data(),
    };
    if command.package_aid.len == 0
        || command.security_domain_aid.len == 0
        || command.load_file_hash.len() != 32
        || command.load_parameters.len() != 4
        || !command.load_token.is_empty()
    {
        return apdu_manager::ApduStatus::wrong_data();
    }
    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::InstallForLoad,
        security_domain::ManagementTarget::Object,
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    if command.security_domain_aid != authority_aid {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }

    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(command.load_file_hash);
    let expected_size = u32::from_be_bytes([
        command.load_parameters[0],
        command.load_parameters[1],
        command.load_parameters[2],
        command.load_parameters[3],
    ]) as usize;
    let install_command = security_domain::InstallForLoadCommand {
        package_aid: command.package_aid,
        security_domain_aid: command.security_domain_aid,
        load_file_hash: command.load_file_hash,
        load_parameters: command.load_parameters,
    };
    let install_status =
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            if !security_domain.may_manage_security_domain_plane()
                || !security_domain.may_access_registry_plane()
            {
                return Some(apdu_manager::ApduStatus::conditions_not_satisfied());
            }
            management_result_to_status(security_domain.install_for_load(&install_command))
        });
    if let Some(status) = install_status {
        return status;
    }

    selected_app::prepare_dynamic_package_load(
        authority_aid,
        command.security_domain_aid,
        command.package_aid,
        is_secure_messaging_command_cla(header.cla),
        expected_size,
        expected_hash,
    )
}

fn handle_load(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    let is_last_block = match header.p1 {
        0x00 => false,
        0x80 => true,
        _ => return apdu_manager::ApduStatus::wrong_data(),
    };
    let incoming_len = apdu.set_incoming_and_receive();
    let protected = is_secure_messaging_command_cla(header.cla);
    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::Load,
        security_domain::ManagementTarget::Object,
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    selected_app::append_dynamic_package_load_block(
        authority_aid,
        protected,
        header.p2,
        is_last_block,
        &apdu.incoming_data()[..incoming_len],
    )
}

fn handle_get_data(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    let tag = match ((header.p1 as u16) << 8) | header.p2 as u16 {
        0x0066 => security_domain::GetDataTag::CardRecognitionData,
        0x0067 => security_domain::GetDataTag::CardCapabilityInformation,
        0x9f70 => security_domain::GetDataTag::LifeCycleState,
        value => security_domain::GetDataTag::Other(value),
    };

    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::GetData,
        security_domain::ManagementTarget::Unspecified,
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    let result = {
        let response = apdu.buffer_mut();
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            if !security_domain.may_access_registry_plane() {
                return Err(security_domain::ManagementError::Rejected);
            }
            security_domain.get_data(tag, response)
        })
    };
    match result {
        Ok(len) => {
            apdu.set_outgoing();
            apdu.set_outgoing_length(len);
            apdu_manager::ApduStatus::success()
        }
        Err(error) => management_error_to_status(error),
    }
}

fn handle_get_status(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    let incoming_len = apdu.set_incoming_and_receive();
    let query =
        match gp_status::parse_query(header.p1, header.p2, &apdu.incoming_data()[..incoming_len]) {
            Ok(query) => query,
            Err(gp_status::GetStatusQueryError::IncorrectP1P2) => {
                set_get_status_cursor(None);
                return apdu_manager::ApduStatus::incorrect_p1_p2();
            }
            Err(gp_status::GetStatusQueryError::WrongData) => {
                set_get_status_cursor(None);
                return apdu_manager::ApduStatus::wrong_data();
            }
        };
    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::GetStatus,
        security_domain::ManagementTarget::Unspecified,
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => {
            set_get_status_cursor(None);
            return status;
        }
    };
    let canonical_query = gp_status::GetStatusQuery {
        next_occurrence: false,
        ..query
    };
    let start_slot = if query.next_occurrence {
        let Some(cursor) = get_status_cursor() else {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        };
        if cursor.authority_aid != authority_aid || cursor.query != canonical_query {
            set_get_status_cursor(None);
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        }
        cursor.next_slot
    } else {
        set_get_status_cursor(None);
        0
    };

    let page = match selected_app::encode_get_status_page(
        &authority_aid,
        canonical_query,
        start_slot,
        apdu.buffer_mut(),
    ) {
        Ok(page) => page,
        Err(_) => {
            set_get_status_cursor(None);
            return apdu_manager::ApduStatus::wrong_data();
        }
    };
    if !page.found {
        set_get_status_cursor(None);
        return apdu_manager::ApduStatus::referenced_data_not_found();
    }

    apdu.set_outgoing();
    apdu.set_outgoing_length(page.len);
    if let Some(next_slot) = page.next_slot {
        set_get_status_cursor(Some(GetStatusCursor {
            authority_aid,
            query: canonical_query,
            next_slot,
        }));
        apdu_manager::ApduStatus::more_data_available()
    } else {
        set_get_status_cursor(None);
        apdu_manager::ApduStatus::success()
    }
}

fn handle_store_data(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    if header.p1 != 0xA0 || header.p2 != 0x00 {
        return apdu_manager::ApduStatus::incorrect_p1_p2();
    }
    let incoming_len = apdu.set_incoming_and_receive();
    let Some(incoming) = stage_management_payload(&apdu.incoming_data()[..incoming_len]) else {
        return apdu_manager::ApduStatus::wrong_length();
    };

    let Some((tag, value)) = parse_single_ber_tlv(incoming) else {
        return apdu_manager::ApduStatus::wrong_data();
    };

    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::StoreData,
        security_domain::ManagementTarget::Object,
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    let command = security_domain::StoreDataCommand { tag, data: value };
    let authorization =
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            if !security_domain.may_access_registry_plane() {
                return Err(security_domain::ManagementError::Rejected);
            }
            security_domain.store_data(&command)
        });
    if let Err(error) = authorization {
        return management_error_to_status(error);
    }

    if selected_app::upsert_registry_data_object(authority_aid, tag, value) {
        apdu_manager::ApduStatus::success()
    } else {
        apdu_manager::ApduStatus::wrong_data()
    }
}

fn handle_put_key(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    let reference = security_domain::PutKeyReferenceControl::decode(header.p1, header.p2);
    let incoming_len = apdu.set_incoming_and_receive();
    let Some(key_data) = stage_management_payload(&apdu.incoming_data()[..incoming_len]) else {
        return apdu_manager::ApduStatus::wrong_length();
    };
    let Some((&new_key_version, encoded_keys)) = key_data.split_first() else {
        return apdu_manager::ApduStatus::wrong_data();
    };
    if new_key_version == 0 || !reference.last_command {
        return apdu_manager::ApduStatus::wrong_data();
    }
    let put_key_command = security_domain::PutKeyCommand {
        key_version: new_key_version,
        key_id: reference.first_key_id,
        key_data: encoded_keys,
    };
    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::PutKey,
        security_domain::ManagementTarget::Key,
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    let put_key_status =
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            management_result_to_status(security_domain.put_key(&put_key_command))
        });
    if let Some(status) = put_key_status {
        return status;
    }

    let owner = authority_aid;
    let mut offset = 0usize;
    let mut entry_index = 0usize;
    let mut stored = false;
    while offset < encoded_keys.len() {
        let key_type = encoded_keys[offset];
        let Some(key_id) = reference.key_id_for_entry(entry_index) else {
            return apdu_manager::ApduStatus::wrong_data();
        };
        let Some(key_len) = encoded_keys.get(offset + 1).copied() else {
            return apdu_manager::ApduStatus::wrong_data();
        };
        let key_len = key_len as usize;
        let start = offset + 2;
        let end = start + key_len;
        let Some(&kcv_len) = encoded_keys.get(end) else {
            return apdu_manager::ApduStatus::wrong_data();
        };
        let next = match end.checked_add(1 + kcv_len as usize) {
            Some(next) if next <= encoded_keys.len() => next,
            _ => return apdu_manager::ApduStatus::wrong_data(),
        };
        let material = &encoded_keys[start..end];
        let inserted = if key_type == 0x88 {
            let usage = match entry_index {
                0 => security_domain::Scp03KeyUsage::Enc,
                1 => security_domain::Scp03KeyUsage::Mac,
                _ => return apdu_manager::ApduStatus::wrong_data(),
            };
            selected_app::upsert_scp03_key_object(owner, new_key_version, key_id, usage, material)
        } else {
            let usage = match key_type {
                0xB1 => 0x11,
                0xB0 => 0x12,
                _ => return apdu_manager::ApduStatus::wrong_data(),
            };
            selected_app::upsert_scp11_key_object(owner, new_key_version, key_id, usage, material)
        };
        if !inserted {
            return apdu_manager::ApduStatus::wrong_data();
        }
        stored = true;
        entry_index += 1;
        offset = next;
    }

    if stored {
        apdu_manager::ApduStatus::success()
    } else {
        apdu_manager::ApduStatus::wrong_data()
    }
}

fn handle_delete(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    if header.p1 != 0x00 || !matches!(header.p2, 0x00 | 0x80) {
        return apdu_manager::ApduStatus::incorrect_p1_p2();
    }
    let incoming_len = apdu.set_incoming_and_receive();
    let incoming = &apdu.incoming_data()[..incoming_len];
    let Some(aid) = parse_delete_aid(incoming) else {
        return apdu_manager::ApduStatus::wrong_data();
    };
    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::Delete,
        management_target_for_aid(&aid),
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    let delete_status =
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            management_result_to_status(security_domain.delete_aid(&aid))
        });
    if let Some(status) = delete_status {
        return status;
    }
    match selected_app::delete_visible_managed_object_under_authority(
        authority_aid,
        &aid,
        header.p2 == 0x80,
    ) {
        selected_app::DeleteManagedObjectResult::Deleted => apdu_manager::ApduStatus::success(),
        selected_app::DeleteManagedObjectResult::NotFound => {
            apdu_manager::ApduStatus::referenced_data_not_found()
        }
        selected_app::DeleteManagedObjectResult::RelatedObjectsExist => {
            apdu_manager::ApduStatus::conditions_not_satisfied()
        }
    }
}

fn handle_set_status(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let header = apdu.header();
    if !set_status_kind_is_supported(header.p1) || !set_status_state_is_supported(header.p2) {
        return apdu_manager::ApduStatus::wrong_data();
    }
    let incoming_len = apdu.set_incoming_and_receive();
    let incoming = &apdu.incoming_data()[..incoming_len];
    let Some(aid) = parse_delete_aid(incoming) else {
        return apdu_manager::ApduStatus::wrong_data();
    };
    let authority_aid = match authorize_management_operation(
        header.cla,
        security_domain::ManagementOperation::SetStatus,
        management_target_for_aid(&aid),
    ) {
        Ok(authority_aid) => authority_aid,
        Err(status) => return status,
    };
    let command = security_domain::SetStatusCommand {
        target_kind: header.p1,
        target_state: header.p2,
        target_aid: aid,
    };
    let set_status =
        security_domain::with_management_authority_aid(authority_aid, |security_domain| {
            management_result_to_status(security_domain.set_status(&command))
        });
    if let Some(status) = set_status {
        return status;
    }
    if selected_app::set_visible_managed_object_status(
        authority_aid,
        command.target_kind,
        command.target_state,
        &command.target_aid,
    ) {
        apdu_manager::ApduStatus::success()
    } else {
        apdu_manager::ApduStatus::referenced_data_not_found()
    }
}

fn set_status_kind_is_supported(p1: u8) -> bool {
    matches!(
        p1,
        security_domain::SET_STATUS_KIND_PACKAGE
            | security_domain::SET_STATUS_KIND_APPLICATION
            | security_domain::SET_STATUS_KIND_SECURITY_DOMAIN
    )
}

fn set_status_state_is_supported(p2: u8) -> bool {
    matches!(
        p2,
        security_domain::SET_STATUS_STATE_UNLOCK | security_domain::SET_STATUS_STATE_LOCK
    )
}

fn management_result_to_status(
    result: Result<(), security_domain::ManagementError>,
) -> Option<apdu_manager::ApduStatus> {
    match result {
        Ok(()) => None,
        Err(error) => Some(management_error_to_status(error)),
    }
}

fn management_error_to_status(error: security_domain::ManagementError) -> apdu_manager::ApduStatus {
    match error {
        security_domain::ManagementError::Rejected => {
            apdu_manager::ApduStatus::conditions_not_satisfied()
        }
        security_domain::ManagementError::Unsupported => {
            apdu_manager::ApduStatus::instruction_not_supported()
        }
        security_domain::ManagementError::NotFound => {
            apdu_manager::ApduStatus::referenced_data_not_found()
        }
    }
}

fn parse_gp_install_command(data: &[u8]) -> Option<GpInstallCommand<'_>> {
    let (package_aid, rest) = parse_lv_field(data)?;
    let (applet_aid, rest) = parse_lv_field(rest)?;
    let (instance_aid, rest) = parse_lv_field(rest)?;
    let (privileges, rest) = parse_lv_field(rest)?;
    let (install_parameters, rest) = parse_lv_field(rest)?;
    let (install_token, rest) = parse_lv_field(rest)?;
    if !rest.is_empty() || !install_token.is_empty() {
        return None;
    }

    Some(GpInstallCommand {
        package_aid: rustlet_runtime::Aid::new(package_aid),
        applet_aid: rustlet_runtime::Aid::new(applet_aid),
        instance_aid: rustlet_runtime::Aid::new(instance_aid),
        privileges,
        install_parameters,
    })
}

fn parse_single_ber_tlv(data: &[u8]) -> Option<(u16, &[u8])> {
    let (&first, mut rest) = data.split_first()?;
    let tag = if first & 0x1f == 0x1f {
        let (&second, tail) = rest.split_first()?;
        if second & 0x80 != 0 {
            return None;
        }
        rest = tail;
        u16::from_be_bytes([first, second])
    } else {
        first as u16
    };
    if tag == 0 {
        return None;
    }
    let (&first_len, tail) = rest.split_first()?;
    let (len, value) = match first_len {
        0x00..=0x7f => (first_len as usize, tail),
        0x81 => {
            let (&len, value) = tail.split_first()?;
            (len as usize, value)
        }
        _ => return None,
    };
    if value.len() != len {
        return None;
    }
    Some((tag, value))
}

fn parse_gp_install_for_load_command(data: &[u8]) -> Option<GpInstallForLoadCommand<'_>> {
    let (package_aid, rest) = parse_lv_field(data)?;
    let (security_domain_aid, rest) = parse_lv_field(rest)?;
    let (load_file_hash, rest) = parse_lv_field(rest)?;
    let (load_parameters, rest) = parse_lv_field(rest)?;
    let (load_token, rest) = parse_lv_field(rest)?;
    if !rest.is_empty() {
        return None;
    }

    Some(GpInstallForLoadCommand {
        package_aid: rustlet_runtime::Aid::new(package_aid),
        security_domain_aid: rustlet_runtime::Aid::new(security_domain_aid),
        load_file_hash,
        load_parameters,
        load_token,
    })
}

fn parse_delete_aid(data: &[u8]) -> Option<rustlet_runtime::Aid> {
    if data.len() >= 2 && data[0] == 0x4f {
        let len = data[1] as usize;
        if data.len() != 2 + len {
            return None;
        }
        return Some(rustlet_runtime::Aid::new(&data[2..]));
    }
    let (aid, rest) = parse_lv_field(data)?;
    if rest.is_empty() {
        Some(rustlet_runtime::Aid::new(aid))
    } else {
        None
    }
}

fn parse_lv_field(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = data.split_first()?;
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}
