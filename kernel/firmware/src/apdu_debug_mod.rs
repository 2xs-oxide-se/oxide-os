const HOST_QUEUE_CAPACITY: usize = 256;

const CASE_EMPTY_HEADER: [u8; 5] = [0x80, 0x00, 0x00, 0x00, 0x00];
const CASE_IN_HEADER: [u8; 5] = [0x80, 0x02, 0x00, 0x00, 0x03];
const CASE_IN_PAYLOAD: [u8; 3] = [0x00, 0x01, 0x02];
const CASE_OUT_HEADER: [u8; 5] = [0x80, 0x04, 0x00, 0x00, 0x04];
const CASE_OUT_WRONG_LE_HEADER: [u8; 5] = [0x80, 0x04, 0x00, 0x00, 0x02];
const CASE_IN_OUT_HEADER: [u8; 5] = [0x80, 0x06, 0x00, 0x00, 0x03];
const CASE_IN_OUT_PAYLOAD: [u8; 3] = [0xAA, 0xBB, 0xCC];
const GET_RESPONSE_THREE: [u8; 5] = [0x00, 0xC0, 0x00, 0x00, 0x03];

const SCP11C_GET_DATA_HEADER: [u8; 5] = [0x80, 0xCA, 0x9F, 0x70, 0x04];
const SCP11C_GET_DATA_RESPONSE: [u8; 7] = [0xCA, 0x9F, 0x70, 0x01, 0x07, 0x90, 0x00];
const SCP11C_MUTUAL_AUTH_BEFORE_PSO_HEADER: [u8; 5] = [0x80, 0x82, 0x00, 0x01, 0x41];
const SCP11C_PSO_HEADER: [u8; 5] = [0x80, 0x2A, 0x00, 0x00, 0xC7];
const SCP11C_HOST_PUBLIC: [u8; 65] = [
    0x04, 0x0C, 0x7F, 0xCC, 0x32, 0x1C, 0x77, 0x11, 0x92, 0x03, 0xDB, 0xE7, 0x98, 0x64, 0x90, 0x7E,
    0x4F, 0x0A, 0x01, 0x91, 0x77, 0x89, 0xDE, 0xA2, 0xD4, 0x73, 0x15, 0x31, 0xA5, 0x2A, 0x22, 0xE2,
    0xBA, 0xC1, 0x76, 0x6D, 0x21, 0xE4, 0x61, 0x7D, 0x72, 0xFB, 0xBE, 0xF8, 0x7D, 0x6E, 0xDF, 0x2D,
    0x8F, 0x80, 0xB5, 0x26, 0x95, 0x6E, 0x3C, 0x2C, 0x17, 0x01, 0xF1, 0x6B, 0x7F, 0x31, 0x15, 0x00,
    0xC6,
];
const SCP11C_OCE_CERTIFICATE: [u8; 199] = [
    0x7F, 0x21, 0x81, 0xC3, 0x93, 0x01, 0x01, 0x42, 0x04, 0x52, 0x4C, 0x4F, 0x53, 0x5F, 0x20, 0x09,
    0x6F, 0x63, 0x65, 0x2D, 0x64, 0x65, 0x62, 0x75, 0x67, 0x95, 0x02, 0x00, 0x80, 0x5F, 0x25, 0x04,
    0x20, 0x24, 0x01, 0x01, 0x5F, 0x24, 0x04, 0x20, 0x34, 0x01, 0x01, 0xBF, 0x20, 0x0D, 0x72, 0x75,
    0x73, 0x74, 0x6C, 0x65, 0x74, 0x6F, 0x73, 0x2D, 0x6F, 0x63, 0x65, 0x7F, 0x49, 0x46, 0xB0, 0x41,
    0x04, 0x0C, 0x7F, 0xCC, 0x32, 0x1C, 0x77, 0x11, 0x92, 0x03, 0xDB, 0xE7, 0x98, 0x64, 0x90, 0x7E,
    0x4F, 0x0A, 0x01, 0x91, 0x77, 0x89, 0xDE, 0xA2, 0xD4, 0x73, 0x15, 0x31, 0xA5, 0x2A, 0x22, 0xE2,
    0xBA, 0xC1, 0x76, 0x6D, 0x21, 0xE4, 0x61, 0x7D, 0x72, 0xFB, 0xBE, 0xF8, 0x7D, 0x6E, 0xDF, 0x2D,
    0x8F, 0x80, 0xB5, 0x26, 0x95, 0x6E, 0x3C, 0x2C, 0x17, 0x01, 0xF1, 0x6B, 0x7F, 0x31, 0x15, 0x00,
    0xC6, 0xF0, 0x01, 0x00, 0x5F, 0x37, 0x40, 0xD6, 0xBA, 0x17, 0x56, 0x97, 0x56, 0xF4, 0x18, 0xE9,
    0x51, 0x93, 0xD3, 0x97, 0x1B, 0xE8, 0x0D, 0x79, 0x62, 0xD8, 0xDB, 0x73, 0xB8, 0x03, 0xCE, 0xB0,
    0xED, 0xEE, 0xB9, 0x42, 0xEA, 0x08, 0x3E, 0x94, 0x11, 0xE8, 0xE8, 0x46, 0xF0, 0xE3, 0x2F, 0x34,
    0x3F, 0x1B, 0x97, 0xD7, 0x59, 0xA8, 0x8E, 0xAA, 0x6F, 0xF0, 0x18, 0xBC, 0xE3, 0x8F, 0xEC, 0x52,
    0x98, 0xCF, 0x4B, 0x6B, 0xA5, 0x61, 0xB6,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScriptProfile {
    Legacy,
    Scp11c,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScriptId {
    Empty,
    In,
    Out,
    OutWrongLeInitial,
    OutWrongLeRetry,
    InOutInitial,
    InOutGetResponse,
    Scp11cGetData,
    Scp11cMutualAuthenticateRejected,
    Scp11cPerformSecurityOperation,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScriptStep {
    Init,
    ExpectByte(u8),
    ExpectSlice { data: &'static [u8], offset: usize },
    Done,
}

struct HostQueue {
    data: [u8; HOST_QUEUE_CAPACITY],
    len: usize,
    offset: usize,
}

impl HostQueue {
    const fn new() -> Self {
        Self {
            data: [0; HOST_QUEUE_CAPACITY],
            len: 0,
            offset: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.offset = 0;
    }

    fn push_slice(&mut self, bytes: &[u8]) {
        if self.len + bytes.len() > self.data.len() {
            panic!("simulate_apdu host queue overflow");
        }

        let start = self.len;
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn pop(&mut self) -> Option<u8> {
        if self.offset >= self.len {
            self.clear();
            return None;
        }

        let byte = self.data[self.offset];
        self.offset += 1;
        if self.offset == self.len {
            self.clear();
        }
        Some(byte)
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.len
    }
}

struct ScriptState {
    profile: ScriptProfile,
    next_script: usize,
    active: Option<ScriptId>,
    step: ScriptStep,
    host_queue: HostQueue,
}

impl ScriptState {
    const fn new() -> Self {
        Self {
            profile: ScriptProfile::Legacy,
            next_script: 0,
            active: None,
            step: ScriptStep::Init,
            host_queue: HostQueue::new(),
        }
    }
}

static mut STATE: ScriptState = ScriptState::new();

/// Initializes the scripted APDU transport without burdening the normal APDU
/// loop with the temporary `ScriptState` used to reset the simulator.
#[inline(never)]
pub fn initialize() {
    unsafe {
        STATE = ScriptState::new();
        STATE.profile = match oxi_core::core::target::execution_env() {
            "simulate_apdu_scp11c" => ScriptProfile::Scp11c,
            _ => ScriptProfile::Legacy,
        };
    }
    oxi_core::consoleln!("simulate_apdu");
}

pub fn prepare_next_command() -> bool {
    let state = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    if state.active.is_some() || !state.host_queue.is_empty() {
        return true;
    }

    let script = match state.profile {
        ScriptProfile::Legacy => match state.next_script {
            0 => ScriptId::Empty,
            1 => ScriptId::In,
            2 => ScriptId::Out,
            3 => ScriptId::OutWrongLeInitial,
            4 => ScriptId::InOutInitial,
            _ => return false,
        },
        ScriptProfile::Scp11c => match state.next_script {
            0 => ScriptId::Scp11cGetData,
            1 => ScriptId::Scp11cMutualAuthenticateRejected,
            2 => ScriptId::Scp11cPerformSecurityOperation,
            _ => return false,
        },
    };

    state.next_script += 1;
    state.active = Some(script);
    state.step = ScriptStep::Init;
    enqueue_header_for(script, &mut state.host_queue);
    true
}

pub fn receive_byte() -> u8 {
    unsafe {
        (*core::ptr::addr_of_mut!(STATE))
            .host_queue
            .pop()
            .unwrap_or_else(|| panic!("simulate_apdu host underflow"))
    }
}

pub fn send_byte(byte: u8) {
    let state = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    let script = state
        .active
        .unwrap_or_else(|| panic!("simulate_apdu received card byte with no active script"));

    state.step = match (script, state.step) {
        (ScriptId::Empty, ScriptStep::Init) => {
            expect_byte(byte, 0x90, ScriptStep::ExpectByte(0x00))
        }
        (ScriptId::Empty, ScriptStep::ExpectByte(0x00)) => {
            expect_byte(byte, 0x00, ScriptStep::Done)
        }

        (ScriptId::In, ScriptStep::Init) => {
            assert_expected(byte, 0x02);
            state.host_queue.push_slice(&CASE_IN_PAYLOAD);
            ScriptStep::ExpectByte(0x90)
        }
        (ScriptId::In, ScriptStep::ExpectByte(0x90)) => {
            expect_byte(byte, 0x90, ScriptStep::ExpectByte(0x00))
        }
        (ScriptId::In, ScriptStep::ExpectByte(0x00)) => expect_byte(byte, 0x00, ScriptStep::Done),

        (ScriptId::Out, ScriptStep::Init) => {
            expect_byte(byte, 0x04, payload_step(&[0x00, 0x01, 0x02, 0x03]))
        }
        (ScriptId::Out, ScriptStep::ExpectSlice { data, offset }) => {
            expect_payload_byte(byte, data, offset)
        }
        (ScriptId::Out, ScriptStep::ExpectByte(0x90)) => {
            expect_byte(byte, 0x90, ScriptStep::ExpectByte(0x00))
        }
        (ScriptId::Out, ScriptStep::ExpectByte(0x00)) => expect_byte(byte, 0x00, ScriptStep::Done),

        (ScriptId::OutWrongLeInitial, ScriptStep::Init) => {
            expect_byte(byte, 0x6C, ScriptStep::ExpectByte(0x04))
        }
        (ScriptId::OutWrongLeInitial, ScriptStep::ExpectByte(0x04)) => {
            expect_byte(byte, 0x04, ScriptStep::Done)
        }

        (ScriptId::OutWrongLeRetry, ScriptStep::Init) => {
            expect_byte(byte, 0x04, payload_step(&[0x00, 0x01, 0x02, 0x03]))
        }
        (ScriptId::OutWrongLeRetry, ScriptStep::ExpectSlice { data, offset }) => {
            expect_payload_byte(byte, data, offset)
        }
        (ScriptId::OutWrongLeRetry, ScriptStep::ExpectByte(0x90)) => {
            expect_byte(byte, 0x90, ScriptStep::ExpectByte(0x00))
        }
        (ScriptId::OutWrongLeRetry, ScriptStep::ExpectByte(0x00)) => {
            expect_byte(byte, 0x00, ScriptStep::Done)
        }

        (ScriptId::InOutInitial, ScriptStep::Init) => {
            assert_expected(byte, 0x06);
            state.host_queue.push_slice(&CASE_IN_OUT_PAYLOAD);
            ScriptStep::ExpectByte(0x61)
        }
        (ScriptId::InOutInitial, ScriptStep::ExpectByte(0x61)) => {
            expect_byte(byte, 0x61, ScriptStep::ExpectByte(0x03))
        }
        (ScriptId::InOutInitial, ScriptStep::ExpectByte(0x03)) => {
            expect_byte(byte, 0x03, ScriptStep::Done)
        }

        (ScriptId::InOutGetResponse, ScriptStep::Init) => {
            expect_byte(byte, 0xC0, payload_step(&[0xCC, 0xBB, 0xAA]))
        }
        (ScriptId::InOutGetResponse, ScriptStep::ExpectSlice { data, offset }) => {
            expect_payload_byte(byte, data, offset)
        }
        (ScriptId::InOutGetResponse, ScriptStep::ExpectByte(0x90)) => {
            expect_byte(byte, 0x90, ScriptStep::ExpectByte(0x00))
        }
        (ScriptId::InOutGetResponse, ScriptStep::ExpectByte(0x00)) => {
            expect_byte(byte, 0x00, ScriptStep::Done)
        }

        (ScriptId::Scp11cGetData, ScriptStep::Init) => {
            expect_byte(byte, 0xCA, payload_step(&SCP11C_GET_DATA_RESPONSE[1..5]))
        }
        (ScriptId::Scp11cGetData, ScriptStep::ExpectSlice { data, offset }) => {
            expect_payload_byte(byte, data, offset)
        }
        (ScriptId::Scp11cGetData, ScriptStep::ExpectByte(0x90)) => {
            expect_byte(byte, 0x90, ScriptStep::ExpectByte(0x00))
        }
        (ScriptId::Scp11cGetData, ScriptStep::ExpectByte(0x00)) => {
            expect_byte(byte, 0x00, ScriptStep::Done)
        }

        (ScriptId::Scp11cMutualAuthenticateRejected, ScriptStep::Init) => {
            assert_expected(byte, 0x82);
            state.host_queue.push_slice(&SCP11C_HOST_PUBLIC);
            ScriptStep::ExpectByte(0x69)
        }
        (ScriptId::Scp11cMutualAuthenticateRejected, ScriptStep::ExpectByte(0x69)) => {
            expect_byte(byte, 0x69, ScriptStep::ExpectByte(0x85))
        }
        (ScriptId::Scp11cMutualAuthenticateRejected, ScriptStep::ExpectByte(0x85)) => {
            expect_byte(byte, 0x85, ScriptStep::Done)
        }

        (ScriptId::Scp11cPerformSecurityOperation, ScriptStep::Init) => {
            assert_expected(byte, 0x2A);
            state.host_queue.push_slice(&SCP11C_OCE_CERTIFICATE);
            ScriptStep::ExpectByte(0x90)
        }
        (ScriptId::Scp11cPerformSecurityOperation, ScriptStep::ExpectByte(0x90)) => {
            expect_byte(byte, 0x90, ScriptStep::ExpectByte(0x00))
        }
        (ScriptId::Scp11cPerformSecurityOperation, ScriptStep::ExpectByte(0x00)) => {
            expect_byte(byte, 0x00, ScriptStep::Done)
        }

        (_, ScriptStep::Done) => panic!("simulate_apdu received extra byte"),
        (_, ScriptStep::ExpectByte(expected)) => {
            assert_expected(byte, expected);
            ScriptStep::Done
        }
        (_, ScriptStep::ExpectSlice { .. }) => panic!("simulate_apdu invalid payload state"),
    };

    if state.step == ScriptStep::Done {
        finish_script(state, script);
    }
}

fn finish_script(state: &mut ScriptState, script: ScriptId) {
    match script {
        ScriptId::Empty => oxi_core::consoleln!("simulate_apdu ok case_empty"),
        ScriptId::In => oxi_core::consoleln!("simulate_apdu ok case_in"),
        ScriptId::Out => oxi_core::consoleln!("simulate_apdu ok case_out"),
        ScriptId::OutWrongLeInitial => {
            oxi_core::consoleln!("simulate_apdu ok case_out_wrong_le_6c");
            state.active = Some(ScriptId::OutWrongLeRetry);
            state.step = ScriptStep::Init;
            enqueue_header_for(ScriptId::OutWrongLeRetry, &mut state.host_queue);
            return;
        }
        ScriptId::OutWrongLeRetry => {
            oxi_core::consoleln!("simulate_apdu ok case_out_wrong_le");
        }
        ScriptId::InOutInitial => {
            oxi_core::consoleln!("simulate_apdu ok case_in_out_61xx");
            state.active = Some(ScriptId::InOutGetResponse);
            state.step = ScriptStep::Init;
            enqueue_header_for(ScriptId::InOutGetResponse, &mut state.host_queue);
            return;
        }
        ScriptId::InOutGetResponse => oxi_core::consoleln!("simulate_apdu ok case_in_out"),
        ScriptId::Scp11cGetData => {
            oxi_core::consoleln!("simulate_apdu scp11c ok get_data_lifecycle");
        }
        ScriptId::Scp11cMutualAuthenticateRejected => {
            oxi_core::consoleln!("simulate_apdu scp11c ok mutual_auth_before_pso_rejected");
        }
        ScriptId::Scp11cPerformSecurityOperation => {
            oxi_core::consoleln!("simulate_apdu scp11c ok perform_security_operation");
        }
    }

    state.active = None;
    state.step = ScriptStep::Init;
}

fn enqueue_header_for(script: ScriptId, queue: &mut HostQueue) {
    match script {
        ScriptId::Empty => queue.push_slice(&CASE_EMPTY_HEADER),
        ScriptId::In => queue.push_slice(&CASE_IN_HEADER),
        ScriptId::Out => queue.push_slice(&CASE_OUT_HEADER),
        ScriptId::OutWrongLeInitial => queue.push_slice(&CASE_OUT_WRONG_LE_HEADER),
        ScriptId::OutWrongLeRetry => queue.push_slice(&CASE_OUT_HEADER),
        ScriptId::InOutInitial => queue.push_slice(&CASE_IN_OUT_HEADER),
        ScriptId::InOutGetResponse => queue.push_slice(&GET_RESPONSE_THREE),
        ScriptId::Scp11cGetData => queue.push_slice(&SCP11C_GET_DATA_HEADER),
        ScriptId::Scp11cMutualAuthenticateRejected => {
            queue.push_slice(&SCP11C_MUTUAL_AUTH_BEFORE_PSO_HEADER)
        }
        ScriptId::Scp11cPerformSecurityOperation => queue.push_slice(&SCP11C_PSO_HEADER),
    }
}

fn payload_step(data: &'static [u8]) -> ScriptStep {
    ScriptStep::ExpectSlice { data, offset: 0 }
}

fn expect_payload_byte(byte: u8, data: &'static [u8], offset: usize) -> ScriptStep {
    if offset >= data.len() {
        panic!("simulate_apdu payload state overflow");
    }

    assert_expected(byte, data[offset]);
    if offset + 1 == data.len() {
        ScriptStep::ExpectByte(0x90)
    } else {
        ScriptStep::ExpectSlice {
            data,
            offset: offset + 1,
        }
    }
}

fn expect_byte(byte: u8, expected: u8, next: ScriptStep) -> ScriptStep {
    assert_expected(byte, expected);
    next
}

fn assert_expected(actual: u8, expected: u8) {
    if actual != expected {
        panic!(
            "simulate_apdu expected {:02X}, got {:02X}",
            expected, actual
        );
    }
}
