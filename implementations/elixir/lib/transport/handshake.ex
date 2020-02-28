defmodule Ockam.Transport.Handshake do
  alias Ockam.Vault

  @key_size 32
  @tag_size 16

  defstruct [
    :id,
    :mode,
    :stage,
    # Preserved data when waiting for more bytes
    :data,
    # {key, nonce} for decryption of incoming data post-handshake
    :decrypt,
    # {key, nonce} for encryption of outgoing data post-handshake
    :encrypt,
    # nonce used during handshake
    :nonce,
    # static key
    :s,
    # static private key (used for computing shared secrets)
    :s_priv,
    # ephemeral public key
    :e,
    # ephemeral private key (used for computing shared secrets)
    :e_priv,
    # remote static public key
    :rs,
    # remote ephemeral public key
    :re,
    # state used for hkdf
    :k,
    # state used for hkdf
    :ck,
    # stateful hash
    :h
  ]

  def step(%__MODULE__{mode: :initiator, stage: stage} = handshake, data) do
    step_initiator(stage, data, handshake)
  end

  def step(%__MODULE__{mode: :responder, stage: stage} = handshake, data) do
    step_responder(stage, data, handshake)
  end

  def initiator do
    id = :erlang.unique_integer()
    handshake = %__MODULE__{mode: :initiator, id: id, stage: 1}

    with {:ok, handshake} <- prologue(handshake) do
      make_initiator_m1(handshake)
    end
  end

  def responder do
    id = :erlang.unique_integer()
    handshake = %__MODULE__{mode: :responder, id: id, stage: 1}
    prologue(handshake)
  end

  def encrypt_outgoing(%__MODULE__{mode: :initiator, encrypt: key} = hs, data) do
    encrypt_outgoing(hs, :encrypt, key, data)
  end

  def encrypt_outgoing(%__MODULE__{mode: :responder, decrypt: key} = hs, data) do
    encrypt_outgoing(hs, :decrypt, key, data)
  end

  def encrypt_outgoing(%__MODULE__{h: h} = hs, field, {ek, en}, data) do
    vector = make_vector(en)
    {:ok, {payload, payload_tag}} = Vault.aes_gcm_encrypt(data, ek, vector, h)
    new_hs = Map.put(hs, field, {ek, en + 1})
    {:ok, new_hs, payload_tag <> payload}
  end

  def decrypt_incoming(%__MODULE__{mode: :initiator, decrypt: key} = hs, data) do
    decrypt_incoming(hs, :decrypt, key, data)
  end

  def decrypt_incoming(%__MODULE__{mode: :responder, encrypt: key} = hs, data) do
    decrypt_incoming(hs, :encrypt, key, data)
  end

  def decrypt_incoming(%__MODULE__{h: h} = hs, field, {ek, en}, data) do
    case data do
      <<payload_tag::binary-size(@tag_size), payload::binary>> ->
        vector = make_vector(en)

        case Vault.aes_gcm_decrypt(payload, ek, vector, h, payload_tag) do
          {:ok, decrypted} ->
            {:ok, Map.put(hs, field, {ek, en + 1}), decrypted}

          {:error, _reason} = err ->
            err
        end

      _ ->
        {:more, @tag_size - byte_size(data)}
    end
  end

  defp prologue(%__MODULE__{id: id} = handshake) do
    with {:ok, {_static_key, static_pubkey, static_privkey}} <- Vault.key_gen_static(id),
         {:ok, {ephemeral_pubkey, ephemeral_privkey}} <- Vault.key_gen_ephemeral(),
         h = "Noise_XX_25519_AESGCM_SHA256",
         ck = "Noise_XX_25519_AESGCM_SHA256",
         {:ok, h} <- mix_hash(h, nil) do
      {:ok,
       %__MODULE__{
         handshake
         | s: static_pubkey,
           s_priv: static_privkey,
           e: ephemeral_pubkey,
           e_priv: ephemeral_privkey,
           nonce: 0,
           h: h,
           k: "",
           ck: ck
       }}
    end
  end

  defp step_initiator(2, data, %__MODULE__{h: h, e: e, e_priv: e_priv} = handshake) do
    c_size = @key_size + @tag_size

    case data do
      <<re::binary-size(@key_size), c::binary-size(c_size), tag2::binary-size(@tag_size),
        rest::binary>> ->
        # 1. Read 32 bytes from the incoming
        #    message buffer, parse it as a public
        #    key, set it to re
        #    h = SHA256(h || re)
        # 2. ck, k = HKDF(ck, DH(e, re), 2)
        #    n = 0
        # 3. Read 48 bytes of the incoming message buffer as c
        #    p = DECRYPT(k, n++, h, c)
        #    h = SHA256(h || c),
        #    parse p as a public key,
        #    set it to rs
        # 4. ck, k = HKDF(ck, DH(e, rs), 2)
        #    n = 0
        # 5. Read remaining bytes of incoming
        #    message buffer as c
        #    p = DECRYPT(k, n++, h, c)
        #    h = SHA256(h || c),
        #    parse p as a payload,
        #    payload should be empty
        with {:ok, h} <- mix_hash(h, re),
             handshake = %__MODULE__{handshake | re: re, h: h},
             {:ok, ck, k} <- hkdf_dh(handshake.ck, e, e_priv, re, @key_size),
             nonce = 0,
             vector = make_vector(nonce),
             handshake = %__MODULE__{handshake | ck: ck, k: k, nonce: nonce},
             <<c::binary-size(@key_size), tag::binary-size(@tag_size)>> = c,
             {:ok, rs} <- Vault.aes_gcm_decrypt(c, k, vector, h, tag),
             {:ok, h} <- mix_hash(h, c <> tag),
             nonce = 1,
             handshake = %__MODULE__{handshake | h: h, rs: rs, nonce: nonce},
             {:ok, ck, k} <- hkdf_dh(handshake.ck, e, e_priv, rs, @key_size),
             nonce = 0,
             vector = make_vector(nonce),
             handshake = %__MODULE__{handshake | ck: ck, k: k, rs: rs, nonce: nonce},
             {:ok, p} <- Vault.aes_gcm_decrypt(rest, k, vector, h, tag2),
             {:ok, h} = mix_hash(h, tag2) do
          if byte_size(p) > 0 do
            {:error, :expected_empty_payload}
          else
            make_initiator_m2(%__MODULE__{handshake | h: h, rs: rs, nonce: 1})
          end
        end

      _ ->
        {:more, @tag_size * 2 + @key_size * 2 - byte_size(data)}
    end
  end

  defp step_initiator(3, data, %__MODULE__{ck: ck} = handshake) do
    # 1. k1, k2 = HKDF(ck, zerolen, 2)
    # n1 = 0, n2 = 0
    # Use (k1, n1) to decrypt incoming
    # Use (k2, n2) to encrypt outgoing
    with {:ok, <<k1::binary-size(@key_size), k2::binary>>} <-
           Vault.hkdf(ck, nil, nil, 2 * @key_size),
         hs = %__MODULE__{handshake | decrypt: {k1, 0}, encrypt: {k2, 0}},
         {:ok, new_hs, decrypted} <- decrypt_incoming(hs, data) do
      case decrypted do
        "SYN_ACK" ->
          {:done, new_hs, nil}

        result ->
          {:error, {:expected_ack, result}}
      end
    end
  end

  defp step_responder(1, data, %__MODULE__{h: h} = handshake) do
    # Read 32 bytes from the incoming message buffer
    # parse it as a public key, set it to re
    # h = SHA256(h || re)
    case data do
      <<re::binary-size(@key_size), rest::binary>> ->
        with {:ok, h} <- mix_hash(h, re),
             {:ok, h} <- mix_hash(h, rest) do
          make_responder_m1(%__MODULE__{handshake | h: h, re: re, stage: 2})
        end

      _ ->
        {:more, @key_size - byte_size(data)}
    end
  end

  defp step_responder(
         2,
         data,
         %__MODULE__{k: k, h: h, nonce: nonce, e: e, e_priv: e_priv} = handshake
       ) do
    # 1. Read 48 bytes the incoming message buffer as c
    # p = DECRYPT(k, n++, h, c)
    # h = SHA256(h || c),
    # parse p as a public key,
    # set it to rs
    case data do
      <<c::binary-size(@key_size), tag::binary-size(@tag_size), rest::binary>> ->
        vector = make_vector(nonce)

        with {:ok, rs} <- Vault.aes_gcm_decrypt(c, k, vector, h, tag),
             {:ok, h} <- mix_hash(h, c <> tag),
             # 2. ck, k = HKDF(ck, DH(e, rs), 2)
             # n = 0
             {:ok, ck, k} <- hkdf_dh(handshake.ck, e, e_priv, rs, @key_size),
             handshake = %__MODULE__{handshake | h: h, ck: ck, k: k, rs: rs},
             nonce = 0,
             # 3. Read remaining bytes of incoming message buffer as c
             # p = DECRYPT(k, n++, h, c)
             # h = SHA256(h || c),
             # parse p as a payload,
             # payload should be empty
             <<tag::binary-size(@tag_size), rest2::binary>> <- rest,
             vector = make_vector(nonce),
             {:ok, _} <- Vault.aes_gcm_decrypt(rest2, k, vector, h, tag),
             nonce = nonce + 1,
             {:ok, h} <- mix_hash(h, tag) do
          make_responder_m2(%__MODULE__{handshake | h: h, nonce: nonce, stage: 3})
        end

      _ ->
        {:more, 48 - byte_size(data)}
    end
  end

  defp make_initiator_m1(%__MODULE__{h: h, e: e} = handshake) do
    # Send ephemeral key
    # h = SHA256(h | ephemeral_pubkey)
    # h = SHA256(h | payload)
    with {:ok, h} <- mix_hash(h, e),
         {:ok, h} <- mix_hash(h, nil) do
      {:ok, %__MODULE__{handshake | h: h, stage: 2}, e}
    end
  end

  defp make_initiator_m2(%__MODULE__{k: k, h: h, nonce: nonce, s: s, s_priv: s_priv} = handshake) do
    # 1. c = ENCRYPT(k, n++, h, s.PublicKey)
    # h =  SHA256(h || c),
    # Write c to outgoing message buffer, big-endian
    # 2. ck, k = HKDF(ck, DH(s, re), 2)
    # n = 0
    # 3. c = ENCRYPT(k, n++, h, payload)
    # h = SHA256(h || c),
    # payload is empty
    vector = make_vector(nonce)

    with {:ok, {c, tag}} <- Vault.aes_gcm_encrypt(s, k, vector, h),
         {:ok, h} <- mix_hash(h, c <> tag),
         handshake = %__MODULE__{handshake | h: h, nonce: nonce + 1},
         {:ok, ck, k} <- hkdf_dh(handshake.ck, s, s_priv, handshake.re, @key_size),
         nonce = 0,
         handshake = %__MODULE__{handshake | ck: ck, k: k, nonce: nonce},
         payload = "",
         vector = make_vector(nonce),
         {:ok, {_c2, tag2}} <- Vault.aes_gcm_encrypt(payload, k, vector, h),
         {:ok, h} <- mix_hash(h, tag2) do
      {:ok, %__MODULE__{handshake | h: h, nonce: nonce + 1, stage: 3}, c <> tag <> tag2}
    end
  end

  defp make_responder_m1(%__MODULE__{e: e, e_priv: e_priv, h: h, s: s} = handshake) do
    # 1. h = SHA256(h || e.PublicKey),
    # Write e.PublicKey to outgoing message buffer, big-endian
    # 2. ck, k = HKDF(ck, DH(e, re), 2)
    # n = 0
    # 3. c = ENCRYPT(k, n++, h, s.PublicKey)
    # h =  SHA256(h || c),
    # Write c to outgoing message buffer
    # 4. ck, k = HKDF(ck, DH(s, re), 2)
    # n = 0
    # 5. c = ENCRYPT(k, n++, h, payload)
    # h = SHA256(h || c),
    # payload is empty
    with {:ok, h} <- mix_hash(h, e),
         {:ok, ck, k} <- hkdf_dh(handshake.ck, e, e_priv, handshake.re, @key_size),
         nonce = 0,
         vector = make_vector(nonce),
         {:ok, {c, tag}} <- Vault.aes_gcm_encrypt(s, k, vector, h),
         {:ok, h} <- mix_hash(h, c <> tag),
         {:ok, ck, k} <- hkdf_dh(ck, handshake.s, handshake.s_priv, handshake.re, @key_size),
         payload = "",
         nonce = 0,
         vector = make_vector(nonce),
         {:ok, {c2, tag2}} <- Vault.aes_gcm_encrypt(payload, k, vector, h),
         nonce = nonce + 1,
         {:ok, h} <- mix_hash(h, c2 <> tag2) do
      new_handshake = %__MODULE__{handshake | nonce: nonce, ck: ck, k: k, h: h}
      {:ok, new_handshake, e <> c <> tag <> tag2}
    end
  end

  defp make_responder_m2(%__MODULE__{ck: ck} = handshake) do
    # 1. k1, k2 = HKDF(ck, zerolen, 2)
    # n1 = 0, n2 = 0
    # Use (k1, n1) to decrypt incoming
    # Use (k2, n2) to encrypt outgoing
    with {:ok, <<k1::binary-size(@key_size), k2::binary>>} <-
           Vault.hkdf(ck, nil, nil, 2 * @key_size),
         hs = %__MODULE__{handshake | decrypt: {k1, 0}, encrypt: {k2, 0}},
         {:ok, new_hs, encrypted} <- encrypt_outgoing(hs, "SYN_ACK") do
      {:done, new_hs, encrypted}
    end
  end

  # HKDF(ck, DH(e, re), 2)
  defp hkdf_dh(ck, _our_pub, our_priv, their_pub, size) do
    # Compute pre-master secret
    with {:ok, secret} <- Vault.ecdh(:x25519, their_pub, our_priv),
         # ck, k = HKDF(ck, pms)
         {:ok, <<ck::binary-size(size), k::binary>>} <- Vault.hkdf(ck, secret, nil, 2 * size) do
      {:ok, ck, k}
    end
  end

  defp mix_hash(hash, nil),
    do: mix_hash(hash, "")

  defp mix_hash(hash, data) when is_binary(data) do
    {:ok, :crypto.hash(:sha256, hash <> data)}
  end

  defp make_vector(nonce) do
    <<0::size(4)-unit(8), nonce::big-unsigned-integer-size(8)>>
  end
end
