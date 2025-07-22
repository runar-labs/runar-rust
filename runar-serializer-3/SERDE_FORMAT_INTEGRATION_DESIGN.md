 let ser_fn: Arc<
            dyn Fn(
                    &ErasedArc,
                    Option<&Arc<KeyStore>>,
                    Option<&dyn LabelResolver>,
                ) -> Result<Vec<u8>>
                + Send
                + Sync,
        > = Arc::new(move |erased, keystore, resolver| {
            let val = erased.as_arc::<T>()?;
            if let (Some(ks), Some(res)) = (keystore, resolver) {
                let result = val.encrypt_with_keystore(ks.as_ref(), res)?;
                serde_cbor::to_vec(&result).map_err(anyhow::Error::from)
            } else {
                serde_cbor::to_vec(&*val).map_err(anyhow::Error::from)
            }   
        });


I our serializer functions for ArcValue we need to be abel to when ks and resolver are provided
we need to call the encrypt_with_keystore() method.. so encrypte types are properly encrypted using the Encrypted types produced by the Encrypted macro.
E.g. 
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize, Encrypt)]
struct TestProfile {

BEcause we  have issues dealign with Encvrypted vs Plain types in runtime.. the best solution so far is to
also have the Plain types to have the same internface.. 
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize, Plain)]
struct SimpleStruct {

so we can always simple call encrypt_with_keystore() and when is a plain type.. then no encryption happens.. just return the type as is.

THe Plain macro is working but the ENcvypt macro is having issues when I tried to add that to the main type. In outr Encpt macro we create extra types to handle the actual encryption. we group fields by labels and each label mighe have different keyes mapped to it via the resolver. to do the encrypt.. so a Type can have field  enctroped with profile keys and other with network keys.

The goal is to make so Plain and Encrypted types have the same internface (trait) that we can call from the ser_fn function.. Idealy we createa a new trait maybe called RunarSerializable instead o using the RunarEncryptable for plain types which is not semantically correct. 

Current behaviour of the Encrypte macro cannos be changes in adverse ways.. still needs to genreate all the Encytped types and handle encryption properly..

I also run in an issues on how these params are handled:
keystore: &KeyStore,
resolver: &dyn LabelResolver,

soemtimes they ar expected to be &Arc<(dyn EnvelopeCrypto + 'static)> wrappe in Arc.. so l;ay attentio ot that also to avoid the same mistake.. use Arc properly as we wnat ot avoid cloning the keystore and label resolver.. the last step is fine to use &KeyStore,  but when crossing boudaries it shold be in an arc.. so we clone the arc and not he undelying obj.

use the test   encryption_test.rs to test your changes.. no need for nrwe tests.. 