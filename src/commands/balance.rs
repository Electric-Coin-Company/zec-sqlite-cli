use anyhow::anyhow;
use gumdrop::Options;

use iso_currency::Currency;
use rust_decimal::{prelude::FromPrimitive, Decimal};
use tracing::{info, warn};
use zcash_client_backend::{data_api::WalletRead, tor};
use zcash_client_sqlite::WalletDb;
use zcash_protocol::value::{Zatoshis, COIN};

use crate::{
    data::{get_db_paths, get_wallet_network},
    error,
    remote::tor_client,
    ui::format_zec,
    MIN_CONFIRMATIONS,
};

// Options accepted for the `balance` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "Convert ZEC values into the given currency")]
    convert: Option<Currency>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params)?;
        let account_id = *db_data
            .get_account_ids()?
            .first()
            .ok_or(anyhow!("Wallet has no accounts"))?;

        let address = db_data
            .get_current_address(account_id)?
            .ok_or(error::Error::InvalidRecipient)?;

        let printer = if let Some(currency) = self.convert {
            let tor = tor_client(wallet_dir.as_ref()).await?;
            ValuePrinter::with_exchange_rate(&tor, currency).await?
        } else {
            ValuePrinter::ZecOnly
        };

        if let Some(wallet_summary) = db_data.get_wallet_summary(MIN_CONFIRMATIONS.into())? {
            let balance = wallet_summary
                .account_balances()
                .get(&account_id)
                .ok_or_else(|| anyhow!("Missing account 0"))?;

            println!("{:#?}", wallet_summary);
            println!("{}", address.encode(&params));
            println!("     Height: {}", wallet_summary.chain_tip_height());
            if let Some(progress) = wallet_summary.scan_progress() {
                println!(
                    "     Synced: {:0.3}%",
                    (*progress.numerator() as f64) * 100f64 / (*progress.denominator() as f64)
                );
            }
            if let Some(progress) = wallet_summary.recovery_progress() {
                println!(
                    "     Recovered: {:0.3}%",
                    (*progress.numerator() as f64) * 100f64 / (*progress.denominator() as f64)
                );
            }
            println!("    Balance: {}", printer.format(balance.total()));
            println!(
                "  Sapling Spendable: {}",
                printer.format(balance.sapling_balance().spendable_value()),
            );
            println!(
                "  Orchard Spendable: {}",
                printer.format(balance.orchard_balance().spendable_value()),
            );
            #[cfg(feature = "transparent-inputs")]
            println!(
                "         Unshielded: {}",
                printer.format(balance.unshielded()),
            );
        } else {
            println!("Insufficient information to build a wallet summary.");
        }

        Ok(())
    }
}

enum ValuePrinter {
    WithConversion { currency: Currency, rate: Decimal },
    ZecOnly,
}

impl ValuePrinter {
    async fn with_exchange_rate(tor: &tor::Client, currency: Currency) -> anyhow::Result<Self> {
        info!("Fetching {:?}/ZEC exchange rate", currency);
        let exchanges = tor::http::cryptex::Exchanges::unauthenticated_known_with_gemini_trusted();
        let usd_zec = tor.get_latest_zec_to_usd_rate(&exchanges).await?;

        if currency == Currency::USD {
            let rate = usd_zec;
            info!("Current {:?}/ZEC exchange rate: {}", currency, rate);
            Ok(Self::WithConversion { currency, rate })
        } else {
            warn!("{:?}/ZEC exchange rate is unsupported", currency);
            Ok(Self::ZecOnly)
        }
    }

    fn format(&self, value: Zatoshis) -> String {
        match self {
            ValuePrinter::WithConversion { currency, rate } => {
                format!(
                    "{} ({}{:.2})",
                    format_zec(value),
                    currency.symbol(),
                    rate * Decimal::from_u64(value.into_u64()).unwrap()
                        / Decimal::from_u64(COIN).unwrap(),
                )
            }
            ValuePrinter::ZecOnly => format_zec(value),
        }
    }
}
