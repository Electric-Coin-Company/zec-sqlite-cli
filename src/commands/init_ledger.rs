/// Initializes a wallet with a Ledger device. This assumes that HW wallet
/// is already containing a Seed Phrase, meaning that the user has gone to the
/// process of generating a new key or restoring it from existing ones using
/// the vendor's proposed workflow. 
/// 
/// A Ledger wallet can only contain a single set of seed bytes (known to the 
/// user as a BIP-0039 mnemonic seed phrase) so this initialization will couple
/// any local data to the device ID for future uses so that users don't mix up
/// devices. On non-ledger workflows this is achieved by using the Seed's
/// Fingerprint but this is not accesible on the ledger code. 
/// 
/// The Ledger device can derive any number of accounts and addresses. This 
/// command will initialize Account index Zero. User will be responsible of 
/// deriving other account indices (this is the same behavior observed in 
/// Ledger Live).
use anyhow::anyhow;
use bip32::{secp256k1::{self, elliptic_curve::{group::GroupEncoding, subtle::CtOption, PublicKey}, PublicKey, Secp256k1}, PublicKey, PublicKeyBytes};
use futures_util::{FutureExt, TryFutureExt};
use gumdrop::Options;
use ledger_zcash::{apdu_extra, app::{self, ZcashApp}, config::{self, AK_SIZE, NSK_SIZE, OVK_SIZE, FVK_SIZE}, types};
use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
use sapling::{keys::SpendValidatingKey, Diversifier, NullifierDerivingKey};
use tracing::dispatcher::get_default;
use zcash_address::unified::{Encoding, Ufvk};
use zcash_client_backend::{
    data_api::{AccountPurpose, WalletWrite, Zip32Derivation},
    proto::service,
};
use zcash_keys::{encoding::decode_extfvk_with_network, keys::UnifiedFullViewingKey};
use zcash_primitives::consensus::NetworkType;
use zcash_protocol::consensus;
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex};
use zx_bip44::BIP44Path;

use crate::{
    config::WalletConfig,
    data::init_dbs,
    remote::{tor_client, Servers},
};

lazy_static::lazy_static! {
    static ref HIDAPI: HidApi = HidApi::new().expect("Failed to create Hidapi");
}

// Options accepted for the `init_ledger` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "a name for the account")]
    name: String,

    #[options(help = "the wallet's birthday (default is current chain height)")]
    birthday: Option<u32>,

    #[options(
        help = "the server to initialize with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,

    #[options(help = "disable connections via TOR")]
    disable_tor: bool,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let opts = self;

        // let (network_type, ufvk) = Ufvk::decode(&opts.fvk)
        //     .map_err(anyhow::Error::new)
        //     .and_then(
        //         |(network, ufvk)| -> Result<(NetworkType, UnifiedFullViewingKey), anyhow::Error> {
        //             let ufvk = UnifiedFullViewingKey::parse(&ufvk)?;
        //             Ok((network, ufvk))
        //         },
        //     )
        //     .or_else(
        //         |_| -> Result<(NetworkType, UnifiedFullViewingKey), anyhow::Error> {
        //             let (network, sfvk) = decode_extfvk_with_network(&opts.fvk)?;
        //             let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(sfvk)?;
        //             Ok((network, ufvk))
        //         },
        //     )?;

        // TODO: get network type from 
        let network = consensus::Network::TestNetwork;
        // match network_type {
        //     NetworkType::Main => consensus::Network::MainNetwork,
        //     NetworkType::Test => consensus::Network::TestNetwork,
        //     NetworkType::Regtest => {
        //         return Err(anyhow!("the regtest network is not supported"));
        //     }
        // };

        // Connect to ledger and retrieve device id or fail
        let app = ZcashApp::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));
        let ledger_id = app.get_device_info()
            .await
            .map_err(anyhow::Error::new)?;
        
        
        // get FVK
        let fvk_bytes = app.get_fvk(0)
            .await
            .map_err(anyhow::Error::new)?;

        // get parts according to https://github.com/Zondax/ledger-zcash/blob/main/docs/APDUSPEC.md
        let mut ak_bytes = [0u8; AK_SIZE];
        bytes.copy_from_slice(&ivk_bytes[0..AK_SIZE]);

        let mut nk_bytes = [0u8; NSK_SIZE];
        bytes.copy_from_slice(&ivk_bytes[AK_SIZE..(AK_SIZE + NSK_SIZE)]);

        let mut ovk_bytes = [0u8; NSK_SIZE];
        bytes.copy_from_slice(&ivk_bytes[(AK_SIZE + NSK_SIZE)..(AK_SIZE + NSK_SIZE + OVK_SIZE)]);


        let ak = match SpendValidatingKey::from_bytes(&ak_bytes) {
            Some(s) => s,
            None => return Err(anyhow!("Failed to parse SpendValidatingKey from bytes")),
        };

        let nk = NullifierDerivingKey::from_bytes(nk_bytes);

        let fvk = FullViewingKey {
            ak,
            nk,
            OutgoingViewingKey { ovk_bytes }
        };
        
        // get diversifier Key
        let dvk_bytes = Self::get_default_div_from(&app, 0)
            .await
            .map_err(|err| anyhow!("failed to get default diversifier from index {} with error: {}", 0, err));
        
        // Create Diversified Full Viewing key
        let dvk = DiversifiableFullViewingKey { dvk_bytes };

        let path = BIP44Path::from_string(format!("m/44'/133'/${}", 0).as_str())
            .map_err(anyhow!("Error mapping path m/44'/133'/${}", 0))?;

        // Obtain Transparent PubKey
        let t_pubkey = app.get_address_unshielded(&path, false)
            .await
            .map_err(op)?;

        
        let pub_key_bytes = PublicKeyBytes::from(t_pubkey.public_key);

        // AccountPubKey(ExtendedPublicKey::new(
        //     public_key,
        //     ExtendedKeyAttrs {
        //         depth: 3,
        //         // We do not expose the inner `ExtendedPublicKey`, so we can use dummy
        //         // values for the fields that are not encoded in an `AccountPubKey`.
        //         parent_fingerprint: [0xff, 0xff, 0xff, 0xff],
        //         child_number: ChildNumber::new(0, true).expect("correct"),
        //         chain_code,
        //     },
        // ));

        // Create UFVK 
        let ufvk = UnifiedFullViewingKey::new(
            None,
            Some(dvk),
            None,
        )
            .map_err(anyhow::new)?;
        
        let server = opts.server.pick(network)?;
        let mut client = if opts.disable_tor {
            server.connect_direct().await?
        } else {
            server.connect(|| tor_client(wallet_dir.as_ref())).await?
        };

        // Get the current chain height (for the wallet's birthday recover-until height).
        let chain_tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        let birthday = super::init::Command::get_wallet_birthday(
            client,
            opts.birthday
                .unwrap_or(chain_tip.saturating_sub(100))
                .into(),
            Some(chain_tip.into()),
        )
        .await?;

        let purpose = AccountPurpose::ViewOnly;

        // Save the wallet config to disk.
        WalletConfig::init_without_mnemonic(wallet_dir.as_ref(), birthday.height(), network)?;

        let mut wallet_db = init_dbs(network, wallet_dir.as_ref())?;
        wallet_db.import_account_ufvk(&opts.name, &ufvk, &birthday, purpose, None)?;

        Ok(())
    }

    /// Retrieve the connected ledger's "ID"
    ///
    /// Uses 44'/1'/0/0/0 derivation path
    /// Note: This is TBD
    async fn get_id(app: &ZcashApp<TransportNativeHID>) -> Result<PublicKey, anyhow::Error> {
        let addr = app.get_address_unshielded(
            &BIP44Path([44 + 0x8000_0000, 1 + 0x8000_0000, 0, 0, 0]),
            false,
        )
        .await
        .map_err(|_| anyhow!("Failed to get unshielded address for \"ID\""))?;
        
        let pub_key = PublicKey::from_sec1_bytes(&addr.public_key)
                .map_err(|_| Err(anyhow!("Failed to generate \"ID\" from public key")))?;

        Ok(pub_key)
    }

    /// Retrieve the defualt diversifier from a given device and path
    ///
    /// The defualt diversifier is the first valid diversifier starting
    /// from index 0
    async fn get_default_div_from(app: &ZcashApp<TransportNativeHID>, idx: u32) -> Result<Diversifier, anyhow::Error> {
        let mut index = DiversifierIndex::new();

        loop {
            let divs = app.get_div_list(idx, index.as_bytes()).await?;
            let divs: &[[u8; 11]] = bytemuck::cast_slice(&divs);

            //find the first div that is not all 0s
            // all 0s is when it's an invalid diversifier
            for div in divs {
                if div != &[0; 11] {
                    return Ok(Diversifier(*div));
                }

                //increment the index for each diversifier returned
                index.increment().map_err(|_| anyhow!("Diversifier Overflow"))?;
            }
        }
    }
}

