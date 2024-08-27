use anyhow::anyhow;
use gumdrop::Options;

use zcash_address::unified::{self, Encoding};
use zcash_client_backend::{
    data_api::{AccountBirthday, AccountPurpose, WalletRead, WalletWrite},
    proto::service,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::consensus;

use crate::{
    error,
    remote::{tor_client, Servers},
};

// Options accepted for the `import-ufvk` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(free, required, help = "The Unified Full Viewing Key to import")]
    ufvk: String,

    #[options(free, required, help = "the UFVK's birthday")]
    birthday: u32,

    #[options(help = "can the wallet omit information needed to spend funds (default is false)")]
    view_only: bool,

    #[options(
        help = "the server to initialize with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,
}

impl Command {
    pub(crate) async fn run<W>(
        self,
        wallet_dir: Option<String>,
        db_data: &mut W,
    ) -> Result<(), anyhow::Error>
    where
        W: WalletWrite + WalletRead,
        <W as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
    {
        let (network, ufvk) = unified::Ufvk::decode(&self.ufvk)?;
        let ufvk = UnifiedFullViewingKey::parse(&ufvk).map_err(|e| anyhow!("{e}"))?;

        let params = match network {
            consensus::NetworkType::Main => Ok(consensus::Network::MainNetwork),
            consensus::NetworkType::Test => Ok(consensus::Network::TestNetwork),
            consensus::NetworkType::Regtest => {
                Err(anyhow!("UFVK is for regtest, which is unsupported"))
            }
        }?;

        // Construct an `AccountBirthday` for the account's birthday.
        let birthday = {
            // Fetch the tree state corresponding to the last block prior to the wallet's
            // birthday height. NOTE: THIS APPROACH LEAKS THE BIRTHDAY TO THE SERVER!
            let mut client = self
                .server
                .pick(params)?
                .connect(|| tor_client(wallet_dir))
                .await?;
            let request = service::BlockId {
                height: (self.birthday - 1).into(),
                ..Default::default()
            };
            let treestate = client.get_tree_state(request).await?.into_inner();
            AccountBirthday::from_treestate(treestate, None).map_err(error::Error::from)?
        };

        // Import the UFVK.
        db_data.import_account_ufvk(
            &ufvk,
            &birthday,
            if self.view_only {
                AccountPurpose::ViewOnly
            } else {
                AccountPurpose::Spending
            },
        )?;

        Ok(())
    }
}
