use std::time::Duration;

use anyhow::anyhow;
use gumdrop::Options;
use minicbor::data::{Int, Tag};
use qrcode::{render::unicode, QrCode};
use tokio::io::{stdout, AsyncWriteExt};
use uuid::Uuid;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_client_sqlite::{AccountUuid, WalletDb};

use crate::{config::WalletConfig, data::get_db_paths, ShutdownListener};

const ZCASH_ACCOUNTS: &str = "zcash-accounts";

#[derive(Debug, Options)]
pub(crate) enum Command {
    #[options(help = "emulate the Keystone enrollment protocol")]
    Enroll(Enroll),
}

// Options accepted for the `keystone enroll` command
#[derive(Debug, Options)]
pub(crate) struct Enroll {
    #[options(free, required, help = "the UUID of the account to enroll")]
    account_id: Uuid,

    #[options(
        help = "the duration in milliseconds to wait between QR codes (default is 500)",
        default = "500"
    )]
    interval: u64,
}

impl Enroll {
    pub(crate) async fn run(
        self,
        mut shutdown: ShutdownListener,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params)?;
        let account_id = AccountUuid::from_uuid(self.account_id);
        let account = db_data
            .get_account(account_id)?
            .ok_or(anyhow!("Account missing: {:?}", account_id))?;

        let key_derivation = account
            .source()
            .key_derivation()
            .ok_or(anyhow!("Cannot enroll account without spending key"))?;

        let mut accounts_packet = vec![];
        minicbor::encode(
            &ZcashAccounts {
                seed_fingerprint: key_derivation.seed_fingerprint().to_bytes(),
                accounts: vec![ZcashUnifiedFullViewingKey {
                    ufvk: account
                        .ufvk()
                        .ok_or(anyhow!("Cannot enroll account without UFVK"))?
                        .encode(&params),
                    index: key_derivation.account_index().into(),
                    name: account.name().map(String::from),
                }],
            },
            &mut accounts_packet,
        )
        .map_err(|e| anyhow!("Failed to encode accounts packet: {:?}", e))?;

        let mut encoder = ur::Encoder::new(&accounts_packet, 100, ZCASH_ACCOUNTS)
            .map_err(|e| anyhow!("Failed to build UR encoder: {e}"))?;

        let mut stdout = stdout();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));
        loop {
            interval.tick().await;

            if shutdown.requested() {
                return Ok(());
            }

            let ur = encoder
                .next_part()
                .map_err(|e| anyhow!("Failed to encode PCZT part: {e}"))?;
            let code = QrCode::new(ur.to_uppercase())?;
            let string = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();

            stdout.write_all(format!("{string}\n").as_bytes()).await?;
            stdout.write_all(format!("{ur}\n\n\n\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
}

struct ZcashAccounts {
    seed_fingerprint: [u8; 32],
    accounts: Vec<ZcashUnifiedFullViewingKey>,
}

struct ZcashUnifiedFullViewingKey {
    ufvk: String,
    index: u32,
    name: Option<String>,
}

const SEED_FINGERPRINT: u8 = 1;
const ACCOUNTS: u8 = 2;
const ZCASH_UNIFIED_FULL_VIEWING_KEY: u64 = 49203;
const UFVK: u8 = 1;
const INDEX: u8 = 2;
const NAME: u8 = 3;

impl<C> minicbor::Encode<C> for ZcashAccounts {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?;

        e.int(Int::from(SEED_FINGERPRINT))?
            .bytes(&self.seed_fingerprint)?;

        e.int(Int::from(ACCOUNTS))?
            .array(self.accounts.len() as u64)?;
        for account in &self.accounts {
            e.tag(Tag::Unassigned(ZCASH_UNIFIED_FULL_VIEWING_KEY))?;
            ZcashUnifiedFullViewingKey::encode(account, e, _ctx)?;
        }

        Ok(())
    }
}

impl<C> minicbor::Encode<C> for ZcashUnifiedFullViewingKey {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2 + u64::from(self.name.is_some()))?;

        e.int(Int::from(UFVK))?.str(&self.ufvk)?;
        e.int(Int::from(INDEX))?.u32(self.index)?;

        if let Some(name) = &self.name {
            e.int(Int::from(NAME))?.str(name)?;
        }

        Ok(())
    }
}
