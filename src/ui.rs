use zcash_primitives::transaction::components::Amount;

const COIN: u64 = 1_0000_0000;

pub(crate) fn format_zec(value: impl Into<Amount>) -> String {
    let value = i64::from(value.into());
    let abs_value = value.abs() as u64;
    let abs_zec = abs_value / COIN;
    let frac = abs_value % COIN;
    let zec = if value.is_negative() {
        -(abs_zec as i64)
    } else {
        abs_zec as i64
    };
    format!("{:3}.{:08} ZEC", zec, frac)
}