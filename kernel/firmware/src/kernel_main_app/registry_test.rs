//! Private diagnostic access to the normal persistent registry (not raw flash).
use super::{ApduFilter, KernelAppModule};
use crate::{apdu_manager::ApduStatus, selected_app};
use rustlet_runtime::SEApdu;

pub(crate) struct Module;
impl KernelAppModule for Module {
    // Normal selected_app initialization restores the registry after module boot.
    fn initialize() {}
}

pub(crate) const APDU_FILTER: ApduFilter = ApduFilter { matches, process };

fn matches(apdu: &dyn SEApdu) -> bool {
    apdu.ins() == 0xa0
}

fn process(apdu: &mut dyn SEApdu) -> ApduStatus {
    if crate::core::flash::persistence_area().page_count == 0 {
        return ApduStatus::conditions_not_satisfied();
    }
    let parent = selected_app::root_security_domain_instance_aid();
    let tag = 0xd000 | u16::from(apdu.p2());
    match apdu.p1() {
        1 => {
            apdu.set_incoming_and_receive();
            if selected_app::upsert_registry_data_object(parent, tag, apdu.incoming_data()) {
                // RAM acceptance only; the host checks durability after reset.
                ApduStatus::success()
            } else {
                ApduStatus::conditions_not_satisfied()
            }
        }
        2 => {
            let _ = apdu.set_outgoing();
            match selected_app::load_registry_data_object(&parent, tag, apdu.buffer_mut()) {
                Some(len) => {
                    // Return directly from shared storage, without chunk copies.
                    apdu.set_outgoing_length(len);
                    ApduStatus::success()
                }
                _ => ApduStatus::conditions_not_satisfied(),
            }
        }
        _ => ApduStatus::wrong_data(),
    }
}
