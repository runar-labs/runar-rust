currently ythe FFI does not expose the runar-keys encrtyption APIS e.g. node_keys_manager
        .encrypt_local_data(file_data_2) decrypt_local_data() encrypt_message_for_mobile() decrypt_message_from_mobile() encrypt_with_envelope*() encrypt_for_public_key() and so on.. there are more.. all of those must be availabnle via FFI

Follow the best practices we used so far for all our FFI interfaces.. avoid footguns and common issues..

the FFI interface does not need to exactl mirror this when there are iossue.. u can define an intermediate step (Using s truct serialize with CBOR for example when makes sense and improve th FFI interaface and etc) apply best practices and common sense.

Behave like an expert C and FFI developer