use lichen_schc::fragment::{FragmentError, FragmentSender};

pub fn fragment_sender(
    payload: &[u8],
    rule_id: u8,
    receiver_limit: usize,
) -> Result<FragmentSender<'_, 'static>, FragmentError> {
    FragmentSender::new_raw(payload, rule_id, receiver_limit)
}
