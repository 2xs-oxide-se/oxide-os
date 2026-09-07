use crate::apdu_layer::{ApduCommand, ApduCompletion, ApduLayer};
use crate::apdu_manager::ApduStatus;
use crate::security_domain::{
    DelegatedSecureChannelHeader, PlainResponseApdu, SecureChannelError,
    SecureChannelEstablishmentCommand, SecureChannelEstablishmentResponseLocation,
    SecureChannelProtocol, WrappedCommandApdu,
};
use oxi_core::core::gp_sm;
use oxi_core::core::scp03;
use rustlet_runtime::{SEApdu, APDU_BUFFER_CAPACITY};

const SECURE_CHANNEL_LAYER_DATA_CAPACITY: usize = APDU_BUFFER_CAPACITY;
const SECURE_CHANNEL_AUX_CAPACITY: usize = gp_sm::PROTECTED_TRANSFORM_CAPACITY + 5;
const SCP11_PSO_CHAIN_CAPACITY: usize = APDU_BUFFER_CAPACITY;

struct Scp11PsoCommandChain {
    active: bool,
    ca_key_version: u8,
    ca_key_id: u8,
    len: usize,
    bytes: [u8; SCP11_PSO_CHAIN_CAPACITY],
}

impl Scp11PsoCommandChain {
    const fn new() -> Self {
        Self {
            active: false,
            ca_key_version: 0,
            ca_key_id: 0,
            len: 0,
            bytes: [0; SCP11_PSO_CHAIN_CAPACITY],
        }
    }

    fn reset(&mut self) {
        self.active = false;
        self.ca_key_version = 0;
        self.ca_key_id = 0;
        self.len = 0;
        self.bytes.fill(0);
    }

    fn append(
        &mut self,
        ca_key_version: u8,
        ca_key_id: u8,
        more_blocks: bool,
        fragment: &[u8],
    ) -> Result<Option<&[u8]>, ApduStatus> {
        if self.active && (self.ca_key_version != ca_key_version || self.ca_key_id != ca_key_id) {
            self.reset();
            return Err(ApduStatus::incorrect_p1_p2());
        }
        if !self.active {
            self.len = 0;
            self.bytes.fill(0);
            self.ca_key_version = ca_key_version;
            self.ca_key_id = ca_key_id;
        }
        let Some(end) = self.len.checked_add(fragment.len()) else {
            self.reset();
            return Err(ApduStatus::wrong_length());
        };
        if end > self.bytes.len() {
            self.reset();
            return Err(ApduStatus::wrong_length());
        }
        self.bytes[self.len..end].copy_from_slice(fragment);
        self.len = end;
        self.active = more_blocks;
        if more_blocks {
            Ok(None)
        } else {
            Ok(Some(&self.bytes[..self.len]))
        }
    }
}

/// Generic secure-channel façade above the T=0 APDU manager.
pub struct SecureChannelLayer<Inner> {
    inner: Inner,
}

impl<Inner> SecureChannelLayer<Inner> {
    pub const fn new(inner: Inner) -> Self {
        Self { inner }
    }

    #[allow(dead_code)]
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }

    fn is_known_establishment_candidate(command: &ApduCommand) -> bool {
        let mode = crate::core::target::secure_channel_mode();
        if !is_gp_secure_channel_cla(command.cla()) {
            return false;
        }
        match command.ins() {
            0x2A => mode.supports_scp11(),
            0x50 => mode.supports_scp03() || mode.is_identity(),
            0x82 if command.p2() == 0x00 => mode.supports_scp03() || mode.is_identity(),
            // In SCP11a/SCP11c, MUTUAL AUTHENTICATE reuses INS 0x82 but uses a
            // non-zero key identifier in P2, unlike SCP02/SCP03.
            0x82 => mode.supports_scp11(),
            // SCP11b opens with INTERNAL AUTHENTICATE.
            0x88 => mode.supports_scp11(),
            _ => false,
        }
    }

    fn is_delegated_establishment_candidate(command: &ApduCommand) -> bool {
        if !is_gp_secure_channel_cla(command.cla())
            || !crate::security_domain::current_security_domain_is_rustlet_backed()
        {
            return false;
        }
        crate::security_domain::current_security_domain().claims_delegated_secure_channel_command(
            DelegatedSecureChannelHeader {
                cla: command.cla(),
                ins: command.ins(),
                p1: command.p1(),
                p2: command.p2(),
                p3: command.p3(),
            },
        )
    }

    fn is_gp_establishment_header(command: &ApduCommand) -> bool {
        is_gp_secure_channel_cla(command.cla())
            && matches!(command.ins(), 0x2A | 0x50 | 0x82 | 0x88)
    }

    fn is_protected_command(command: &ApduCommand) -> bool {
        // Invariant: CLA bit 0x04 marks a GP secure messaging command in the
        // command families currently supported by Oxide SE.
        (command.cla() & 0x04) != 0
    }

    fn is_select_command(command: &ApduCommand) -> bool {
        command.ins() == 0xA4
    }

    fn is_profiled_out_rmac_command(command: &ApduCommand) -> bool {
        is_profiled_out_rmac_header(command.cla(), command.ins())
    }

    fn command_header_bytes(command: &ApduCommand) -> [u8; 5] {
        [
            command.cla(),
            command.ins(),
            command.p1(),
            command.p2(),
            command.p3(),
        ]
    }

    fn is_transparent_stack_probe(command: &ApduCommand) -> bool {
        crate::kernel_main_app::preserves_clear_apdu_session(command)
    }
}

impl<Inner: ApduLayer> SecureChannelLayer<Inner> {
    fn handle_establishment(&mut self, command: &mut ApduCommand, delegated: bool) -> ApduStatus {
        let security_domain = crate::security_domain::current_security_domain();
        if security_domain.session_state().secure_channel_open() {
            // GP starts a new establishment exchange from a terminated prior
            // session, never by retaining old command or response chains.
            security_domain.reset_secure_channel();
        }
        let authority_aid = crate::selected_app::active_security_domain_instance_aid();
        if !crate::selected_app::security_domain_may_open_secure_channel(&authority_aid) {
            return ApduStatus::conditions_not_satisfied();
        }
        let cla = command.cla();
        let ins = command.ins();
        let p1 = command.p1();
        let p2 = command.p2();
        let p3 = command.p3();
        let response_scratch = secure_channel_aux_scratch_mut();
        let result = {
            let mut apdu = command.as_apdu();
            let incoming_len = apdu.set_incoming_and_receive();
            let data = &apdu.incoming_data()[..incoming_len];
            let mut establishment = SecureChannelEstablishmentCommand {
                cla,
                ins,
                p1,
                p2,
                p3,
                data,
            };
            if !delegated && ins == 0x2A {
                if (p2 & 0x80) != 0 {
                    scp11_pso_command_chain_mut().reset();
                    return ApduStatus::incorrect_p1_p2();
                }
                let ca_key_version = p1 & 0x7F;
                let ca_key_id = p2 & 0x7F;
                let chain = scp11_pso_command_chain_mut();
                if chain.active || (p1 & 0x80) != 0 {
                    match chain.append(ca_key_version, ca_key_id, (p1 & 0x80) != 0, data) {
                        Ok(None) => return ApduStatus::success(),
                        Ok(Some(certificate)) => establishment.data = certificate,
                        Err(status) => return status,
                    }
                }
                establishment.p1 = ca_key_version;
                establishment.p2 = ca_key_id;
            }
            if delegated {
                crate::security_domain::current_security_domain()
                    .handle_delegated_secure_channel_command(&establishment)
            } else {
                crate::security_domain::current_security_domain()
                    .handle_establishment(&establishment, response_scratch)
            }
        };

        match result {
            Ok(result) => {
                if result.response_len > rustlet_runtime::APDU_PAYLOAD_LENGTH_MAX {
                    return ApduStatus::wrong_length();
                }
                match result.response_location {
                    SecureChannelEstablishmentResponseLocation::None => {
                        if result.response_len != 0 {
                            return ApduStatus::wrong_length();
                        }
                    }
                    SecureChannelEstablishmentResponseLocation::CallerScratch => {
                        if result.response_len > response_scratch.len() {
                            return ApduStatus::wrong_length();
                        }
                        let mut apdu = command.as_apdu();
                        apdu.set_outgoing();
                        apdu.buffer_mut()[..result.response_len]
                            .copy_from_slice(&response_scratch[..result.response_len]);
                        apdu.set_outgoing_length(result.response_len);
                    }
                    SecureChannelEstablishmentResponseLocation::SharedApduPayload => {
                        // SDDISPATCH has already published the bytes in the
                        // transport payload. Only transport metadata changes.
                        let mut apdu = command.as_apdu();
                        apdu.set_outgoing();
                        apdu.set_outgoing_length(result.response_len);
                    }
                }
                ApduStatus::success()
            }
            Err(error) => secure_channel_error_to_status(error),
        }
    }

    fn unwrap_command_if_needed(&mut self, command: &mut ApduCommand) -> Result<bool, ApduStatus> {
        if crate::core::target::secure_channel_mode().is_identity() {
            return Ok(false);
        }
        let session_state = crate::security_domain::current_security_domain().session_state();
        if !Self::is_protected_command(command) {
            if matches!(
                session_state.protocol,
                Some(SecureChannelProtocol::Scp11(_))
            ) && session_state.secure_channel_open()
                && !crate::kernel_main_app::preserves_clear_apdu_session(command)
            {
                crate::security_domain::current_security_domain().reset_secure_channel();
                if Self::is_select_command(command) {
                    // Application selection terminates SCP11 and then proceeds
                    // as an ordinary clear SELECT command.
                    return Ok(false);
                }
                return Err(ApduStatus::conditions_not_satisfied());
            }
            return Ok(false);
        }
        let displaced_app =
            crate::selected_app::ensure_active_security_domain_loaded_for_secure_channel()?;
        let security_domain = crate::security_domain::current_security_domain();
        let session_state = security_domain.session_state();
        if !session_state.secure_channel_open() {
            return Err(ApduStatus::conditions_not_satisfied());
        }
        let protect_response = session_state.protects_response();
        let incoming_len = command.receive_incoming_for_layer();
        let incoming = command.incoming_data_for_layer();
        let mac_len = session_state.mac_len;
        if mac_len == 0 {
            return Err(ApduStatus::wrong_length());
        }
        let header = Self::command_header_bytes(command);
        let mut transform = secure_channel_transform_scratch();
        let data_len = match unwrap_protected_command(
            security_domain,
            header,
            &incoming[..incoming_len],
            mac_len,
            transform.bytes_mut(),
        ) {
            Ok(data_len) => data_len,
            Err(status) => {
                if status == ApduStatus::security_status_not_satisfied() {
                    // GP cryptographic security errors abort the current
                    // secure-channel state. Structural APDU errors retain the
                    // session so the host can correct and retransmit them.
                    security_domain.reset_secure_channel();
                }
                return Err(status);
            }
        };

        if !command.replace_incoming_for_layer(&transform.bytes_mut()[..data_len]) {
            return Err(ApduStatus::wrong_length());
        }
        transform.finish();
        let status = crate::selected_app::restore_selected_app_after_secure_channel(displaced_app);
        if status.sw1 != 0x90 || status.sw2 != 0x00 {
            return Err(status);
        }
        Ok(protect_response)
    }

    fn wrap_response_if_needed(
        &mut self,
        completion: &mut ApduCompletion<'_>,
    ) -> Result<(), ApduStatus> {
        if crate::core::target::secure_channel_mode().is_identity() {
            return Ok(());
        }
        if !Self::is_protected_command(completion.command()) {
            return Ok(());
        }
        if !completion.command().secure_response_required() {
            return Ok(());
        }
        let status = completion.status;
        let status_word = (status.sw1, status.sw2);
        let rustlet_backed = crate::security_domain::current_security_domain_is_rustlet_backed();
        let wrapped_len = if rustlet_backed {
            let plain_response = completion.command().outgoing_data_for_layer();
            let scratch = secure_channel_aux_scratch_mut();
            if plain_response.len() > scratch.len() {
                return Err(ApduStatus::wrong_length());
            }
            // SDDISPATCH republishes both halves of the shared Rustlet page.
            // Only the proxy path must preserve application output while the
            // resident Rustlet Security Domain handles the response.
            scratch[..plain_response.len()].copy_from_slice(plain_response);
            let plain_len = plain_response.len();
            let _displaced_app =
                crate::selected_app::ensure_active_security_domain_loaded_for_secure_channel()?;
            encode_secure_channel_response(&scratch[..plain_len], status_word)?
        } else {
            let _displaced_app =
                crate::selected_app::ensure_active_security_domain_loaded_for_secure_channel()?;
            encode_secure_channel_response(
                completion.command().outgoing_data_for_layer(),
                status_word,
            )?
        };

        if completion.outgoing_length() == 0 {
            let mut apdu = completion.command_mut().as_apdu();
            apdu.set_outgoing();
            apdu.set_outgoing_length(0);
        }
        let mut transform = secure_channel_transform_scratch();
        if !completion
            .command_mut()
            .replace_outgoing_for_layer(&transform.bytes_mut()[..wrapped_len])
        {
            return Err(ApduStatus::wrong_length());
        }
        transform.finish();
        Ok(())
    }
}

impl<Inner: ApduLayer> ApduLayer for SecureChannelLayer<Inner> {
    fn send_atr(&mut self, historical_bytes: &[u8]) {
        self.inner.send_atr(historical_bytes);
    }

    fn receive_command(&mut self) -> Option<ApduCommand> {
        loop {
            let mut command = self.inner.receive_command()?;

            if command.ins() != 0x2A && !Self::is_transparent_stack_probe(&command) {
                scp11_pso_command_chain_mut().reset();
            }
            if Self::is_profiled_out_rmac_command(&command) {
                self.inner
                    .complete_command(command.complete(ApduStatus::instruction_not_supported()));
                continue;
            }
            let known_establishment = Self::is_known_establishment_candidate(&command);
            let delegated_establishment =
                !known_establishment && Self::is_delegated_establishment_candidate(&command);
            if known_establishment || delegated_establishment {
                let status = self.handle_establishment(&mut command, delegated_establishment);
                self.inner.complete_command(command.complete(status));
                continue;
            }
            if Self::is_gp_establishment_header(&command) {
                // Preserve the T=0 exchange shape even when no compiled engine
                // and no Rustlet Security Domain claims the command.
                command.receive_incoming_for_layer();
                self.inner
                    .complete_command(command.complete(ApduStatus::instruction_not_supported()));
                continue;
            }

            let protect_response = match self.unwrap_command_if_needed(&mut command) {
                Ok(protect_response) => protect_response,
                Err(status) => {
                    self.inner.complete_command(command.complete(status));
                    continue;
                }
            };
            // Invariant: response policy belongs to this exact command. It is
            // captured before application dispatch because restoring a
            // Rustlet-backed Security Domain rewrites the shared APDU page.
            command.set_secure_response_required(protect_response);

            return Some(command);
        }
    }

    fn complete_command(&mut self, mut completion: ApduCompletion<'_>) {
        if let Err(status) = self.wrap_response_if_needed(&mut completion) {
            let failed_completion = ApduCompletion {
                command: completion.command,
                status,
            };
            self.inner.complete_command(failed_completion);
            return;
        }

        self.inner.complete_command(completion);
    }
}

static mut SECURE_CHANNEL_AUX_SCRATCH: [u8; SECURE_CHANNEL_AUX_CAPACITY] =
    [0; SECURE_CHANNEL_AUX_CAPACITY];
static mut SECURE_CHANNEL_PROXY_DATA_SCRATCH: [u8; SECURE_CHANNEL_LAYER_DATA_CAPACITY] =
    [0; SECURE_CHANNEL_LAYER_DATA_CAPACITY];
static mut SECURE_CHANNEL_MAC_SCRATCH: [u8; scp03::S16_MAC_LEN] = [0; scp03::S16_MAC_LEN];
static mut SCP11_PSO_COMMAND_CHAIN: Scp11PsoCommandChain = Scp11PsoCommandChain::new();

fn secure_channel_aux_scratch_mut() -> &'static mut [u8] {
    // Invariant: the APDU loop is single-threaded. Establishment responses and
    // Rustlet-backed response wrapping own this scratch at disjoint times.
    unsafe { &mut *core::ptr::addr_of_mut!(SECURE_CHANNEL_AUX_SCRATCH) }
}

fn secure_channel_transform_scratch(
) -> crate::apdu_manager::SecondaryBuffer<crate::apdu_manager::SecondaryCryptoScratch> {
    if crate::security_domain::current_security_domain_is_rustlet_backed() {
        // A proxy call owns and rewrites the shared control half, so its result
        // must be staged outside the Rustlet page.
        return crate::apdu_manager::acquire_proxy_crypto_scratch(unsafe {
            &mut *core::ptr::addr_of_mut!(SECURE_CHANNEL_PROXY_DATA_SCRATCH)
        });
    }
    crate::apdu_manager::acquire_secondary_buffer().begin_crypto()
}

fn secure_channel_mac_scratch_mut() -> &'static mut [u8] {
    // Invariant: response MAC bytes are transient and paired with the current
    // use of `SECURE_CHANNEL_DATA_SCRATCH`.
    unsafe { &mut *core::ptr::addr_of_mut!(SECURE_CHANNEL_MAC_SCRATCH) }
}

fn scp11_pso_command_chain_mut() -> &'static mut Scp11PsoCommandChain {
    // Invariant: only the single-threaded APDU loop advances or cancels PSO
    // command chaining, and no reference survives one establishment call.
    unsafe { &mut *core::ptr::addr_of_mut!(SCP11_PSO_COMMAND_CHAIN) }
}

fn unwrap_protected_command(
    security_domain: &mut dyn crate::security_domain::SecurityDomain,
    header: [u8; 5],
    incoming: &[u8],
    mac_len: usize,
    out: &mut [u8],
) -> Result<usize, ApduStatus> {
    let data_len = incoming
        .len()
        .checked_sub(mac_len)
        .ok_or_else(ApduStatus::wrong_length)?;
    if data_len > SECURE_CHANNEL_LAYER_DATA_CAPACITY {
        return Err(ApduStatus::wrong_length());
    }
    let wrapped =
        WrappedCommandApdu::new(&header, incoming, data_len, 0, data_len, data_len, mac_len)
            .ok_or_else(ApduStatus::wrong_length)?;

    security_domain
        .unwrap_command_into(&wrapped, out)
        .map_err(secure_messaging_error_to_status)
}

fn encode_secure_channel_response(
    plain_response: &[u8],
    status: (u8, u8),
) -> Result<usize, ApduStatus> {
    let security_domain = crate::security_domain::current_security_domain();
    if !security_domain.session_state().secure_channel_open() {
        return Err(ApduStatus::conditions_not_satisfied());
    }
    let mut transform = secure_channel_transform_scratch();
    let mac = secure_channel_mac_scratch_mut();
    let wrapped_lengths = security_domain
        .wrap_response_into(
            &PlainResponseApdu {
                bytes: plain_response,
                status,
            },
            transform.bytes_mut(),
            mac,
        )
        .map_err(secure_channel_error_to_status)?;
    let wrapped_len = wrapped_lengths
        .data_len
        .checked_add(wrapped_lengths.mac_len)
        .filter(|len| *len <= transform.bytes_mut().len())
        .ok_or_else(ApduStatus::wrong_length)?;
    transform.bytes_mut()[wrapped_lengths.data_len..wrapped_len]
        .copy_from_slice(&mac[..wrapped_lengths.mac_len]);
    transform.finish();
    Ok(wrapped_len)
}

const fn is_gp_secure_channel_cla(cla: u8) -> bool {
    cla == 0x80 || cla == 0x84
}

const fn is_profiled_out_rmac_header(cla: u8, ins: u8) -> bool {
    is_gp_secure_channel_cla(cla) && matches!(ins, 0x78 | 0x7A)
}

fn secure_channel_error_to_status(error: SecureChannelError) -> ApduStatus {
    match error {
        SecureChannelError::Rejected => ApduStatus::conditions_not_satisfied(),
        SecureChannelError::Unsupported => ApduStatus::instruction_not_supported(),
        SecureChannelError::Status(status) => status,
    }
}

fn secure_messaging_error_to_status(error: SecureChannelError) -> ApduStatus {
    match error {
        SecureChannelError::Rejected => ApduStatus::security_status_not_satisfied(),
        SecureChannelError::Unsupported => ApduStatus::instruction_not_supported(),
        SecureChannelError::Status(status) if status == ApduStatus::conditions_not_satisfied() => {
            ApduStatus::security_status_not_satisfied()
        }
        SecureChannelError::Status(status) => status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establishment_and_secure_messaging_rejections_have_distinct_status_words() {
        assert_eq!(
            secure_channel_error_to_status(SecureChannelError::Rejected),
            ApduStatus::conditions_not_satisfied()
        );
        assert_eq!(
            secure_messaging_error_to_status(SecureChannelError::Rejected),
            ApduStatus::security_status_not_satisfied()
        );
        assert_eq!(
            secure_messaging_error_to_status(SecureChannelError::Status(
                ApduStatus::conditions_not_satisfied(),
            )),
            ApduStatus::security_status_not_satisfied()
        );
    }

    #[test]
    fn scp11_pso_command_chain_reassembles_consecutive_fragments() {
        let mut chain = Scp11PsoCommandChain::new();
        assert_eq!(chain.append(1, 2, true, b"cert-"), Ok(None));
        assert_eq!(
            chain.append(1, 2, false, b"body"),
            Ok(Some(b"cert-body".as_slice()))
        );
    }

    #[test]
    fn scp11_pso_command_chain_rejects_selector_change_and_overflow() {
        let mut chain = Scp11PsoCommandChain::new();
        assert_eq!(chain.append(1, 2, true, b"first"), Ok(None));
        assert_eq!(
            chain.append(1, 3, false, b"second"),
            Err(ApduStatus::incorrect_p1_p2())
        );
        assert!(!chain.active);

        let oversized = [0xA5; SCP11_PSO_CHAIN_CAPACITY];
        assert_eq!(chain.append(1, 2, true, &oversized), Ok(None));
        assert_eq!(
            chain.append(1, 2, false, &[0x5A]),
            Err(ApduStatus::wrong_length())
        );
        assert!(!chain.active);
    }

    #[test]
    fn selected_profile_intercepts_only_gp_rmac_session_commands() {
        assert!(is_profiled_out_rmac_header(0x80, 0x7A));
        assert!(is_profiled_out_rmac_header(0x84, 0x78));
        assert!(!is_profiled_out_rmac_header(0x00, 0x7A));
        assert!(!is_profiled_out_rmac_header(0x80, 0x82));
    }
}
